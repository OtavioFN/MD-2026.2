/*
 * decoder.c - Criptografia RSA (Matemática Discreta - UFAL)
 *
 * O que o programa faz:
 *   1. Lê UMA linha JSON da entrada padrão (stdin), por exemplo:
 *        {"ciphertext":[524,2185,2271],"private_key":{"n":3233,"d":2753}}
 *   2. Desfaz a cifragem de cada número usando a chave privada (n, d).
 *   3. Imprime UMA linha JSON na saída padrão (stdout), por exemplo:
 *        {"message":"Bom"}
 *
 * A matemática (uma vez para cada número cifrado):
 *        c = número cifrado
 *        m = c^d mod n          <- código ASCII do caractere original
 *
 * Por que funciona? Porque d é o inverso de e módulo phi(n), ou seja,
 * (m^e)^d = m^(e*d) = m (mod n). Decifrar é "desfazer" o que o encoder fez.
 *
 * Compilação:
 *   gcc -std=c11 -Wall -Wextra -Werror -O2 decoder.c -o decoder
 *
 * Ordem sugerida de leitura:
 *   main -> descriptografar -> exponenciacao_modular -> multiplicacao_modular
 *   (as funções de leitura do JSON ficam por último: são só "encanamento").
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Nomes mais curtos para os tipos inteiros grandes que vamos usar. */
typedef unsigned long long inteiro64;   /* 64 bits: vai até ~1,8 * 10^19  */
typedef unsigned __int128  inteiro128;  /* 128 bits: guarda produtos de dois números de 64 bits */

/* Tamanhos dos "vetores" (arrays). A spec exige no mínimo 1000 caracteres. */
#define TAMANHO_MAX_ENTRADA   (1u << 21)   /* o JSON de entrada: 2 MiB      */
#define TAMANHO_MAX_MENSAGEM  (1u << 16)   /* a mensagem: 65536 caracteres  */


/* ====================================================================== */
/*  PARTE 1 - MATEMÁTICA: aritmética modular                              */
/* ====================================================================== */

/*
 * Calcula (a * b) mod modulo.
 *
 * Por que não escrever simplesmente (a * b) % modulo?
 * Porque, com primos de até 9 dígitos, n chega perto de 10^18 e o produto
 * a * b pode chegar a 10^36, que NÃO cabe em 64 bits (estouraria e daria
 * resultado errado). Por isso fazemos a conta em 128 bits e só depois
 * tiramos o resto, que volta a caber em 64 bits.
 */
static inteiro64 multiplicacao_modular(inteiro64 a, inteiro64 b, inteiro64 modulo)
{
    inteiro128 produto = (inteiro128)a * (inteiro128)b;
    return (inteiro64)(produto % modulo);
}

/*
 * Calcula base^expoente mod modulo de forma RÁPIDA (exponenciação rápida,
 * também chamada "square-and-multiply").
 *
 * Ideia: em vez de multiplicar a base 'expoente' vezes (impossível quando o
 * expoente é enorme, como o d), usamos os bits do expoente em binário.
 *
 * Exemplo: 3^13 mod 100, com 13 = 1101 em binário (13 = 8 + 4 + 1):
 *   3^13 = 3^8 * 3^4 * 3^1
 * Vamos elevando a base ao quadrado (3, 3^2, 3^4, 3^8, ...) e só
 * multiplicamos no resultado quando o bit correspondente do expoente é 1.
 * São ~log2(expoente) passos em vez de 'expoente' passos.
 */
static inteiro64 exponenciacao_modular(inteiro64 base, inteiro64 expoente, inteiro64 modulo)
{
    inteiro64 resultado = 1 % modulo;   /* "1 % modulo" cobre o caso modulo == 1 */
    base = base % modulo;

    while (expoente > 0) {
        if (expoente & 1ULL) {                       /* o bit atual do expoente é 1? */
            resultado = multiplicacao_modular(resultado, base, modulo);
        }
        base = multiplicacao_modular(base, base, modulo);   /* eleva a base ao quadrado */
        expoente = expoente >> 1;                           /* passa para o próximo bit */
    }
    return resultado;
}


/* ====================================================================== */
/*  PARTE 2 - DESENCRIPTAÇÃO (função com nome exigido pela spec)          */
/* ====================================================================== */

/*
 * Desfaz a cifragem de cada número de 'texto_cifrado' com a chave privada (n, d).
 *
 * Guarda os caracteres recuperados em 'mensagem', na mesma ordem dos
 * números, e devolve quantos caracteres foram gerados (um por número).
 */
static size_t descriptografar(const inteiro64 *texto_cifrado, size_t quantidade,
                              inteiro64 n, inteiro64 d,
                              char *mensagem)
{
    for (size_t i = 0; i < quantidade; i++) {
        /* m = c^d mod n  ->  o código ASCII do caractere original */
        inteiro64 codigo_ascii = exponenciacao_modular(texto_cifrado[i], d, n);

        mensagem[i] = (char)codigo_ascii;
    }
    return quantidade;
}


/* ====================================================================== */
/*  PARTE 3 - LEITURA DO JSON (só "encanamento", sem matemática)          */
/* ====================================================================== */
/*
 * Não usamos biblioteca de JSON. Como o formato é fixo e simples, basta
 * procurar o nome de cada campo no texto e ler o valor que vem depois.
 */

/* Avança o ponteiro enquanto houver espaço, tab ou quebra de linha. */
static const char *pular_espacos(const char *p)
{
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
        p++;
    }
    return p;
}

/*
 * Procura o campo "nome" a partir de 'inicio' e devolve um ponteiro para o
 * começo do VALOR dele (logo depois dos dois pontos). Devolve NULL se não achar.
 *
 * Exemplo: em   {"n":3233,"d":2753}   procurando "d" devolve um ponteiro para "2753}".
 */
static const char *encontrar_valor(const char *inicio, const char *nome)
{
    char procurado[32];
    snprintf(procurado, sizeof(procurado), "\"%s\"", nome);   /* monta  "nome"  com as aspas */

    const char *achado = strstr(inicio, procurado);
    if (achado == NULL) {
        return NULL;
    }

    const char *p = pular_espacos(achado + strlen(procurado));
    if (*p != ':') {
        return NULL;
    }
    return pular_espacos(p + 1);
}

/*
 * Lê um número inteiro positivo que começa em 'p' e guarda em 'valor'.
 * Devolve um ponteiro para o caractere logo DEPOIS do número (útil para
 * continuar lendo a lista), ou NULL se não houver um número ali.
 */
static const char *ler_numero(const char *p, inteiro64 *valor)
{
    if (p == NULL || *p < '0' || *p > '9') {
        return NULL;
    }
    char *fim;
    *valor = strtoull(p, &fim, 10);
    return fim;
}

/*
 * Lê uma lista de números no formato [a,b,c] que começa em 'p'
 * (o '[' deve estar em p) e guarda os números em 'lista'.
 * Devolve quantos números foram lidos, ou (size_t)-1 se algo estiver errado.
 */
static size_t ler_lista(const char *p, inteiro64 *lista, size_t capacidade)
{
    if (p == NULL || *p != '[') {
        return (size_t)-1;
    }
    p = pular_espacos(p + 1);             /* pula o '[' */

    size_t quantidade = 0;

    if (*p == ']') {
        return 0;                         /* lista vazia: [] */
    }

    while (1) {
        if (quantidade >= capacidade) {
            return (size_t)-1;            /* lista grande demais */
        }

        p = ler_numero(pular_espacos(p), &lista[quantidade]);
        if (p == NULL) {
            return (size_t)-1;            /* não era um número */
        }
        quantidade++;

        p = pular_espacos(p);
        if (*p == ',') {
            p++;                          /* tem mais números: continua */
        } else if (*p == ']') {
            return quantidade;            /* fim da lista */
        } else {
            return (size_t)-1;            /* caractere inesperado */
        }
    }
}


/* ====================================================================== */
/*  PARTE 4 - MAIN                                                        */
/* ====================================================================== */

/* Ficam fora do main (static) porque são grandes demais para a pilha. */
static char       entrada[TAMANHO_MAX_ENTRADA];
static inteiro64  texto_cifrado[TAMANHO_MAX_MENSAGEM];
static char       mensagem[TAMANHO_MAX_MENSAGEM];

int main(void)
{
    /* 1. Lê tudo o que veio no stdin e termina o texto com '\0'. */
    size_t bytes_lidos = fread(entrada, 1, sizeof(entrada) - 1, stdin);
    entrada[bytes_lidos] = '\0';

    /* 2. Localiza os campos "ciphertext" e "private_key" no JSON. */
    const char *valor_lista = encontrar_valor(entrada, "ciphertext");
    const char *valor_chave = encontrar_valor(entrada, "private_key");
    if (valor_lista == NULL || valor_chave == NULL) {
        printf("{\"error\":\"entrada invalida\"}\n");
        return 1;
    }

    /* 3. Extrai a lista de números cifrados e os números n e d (de dentro de "private_key"). */
    size_t quantidade = ler_lista(valor_lista, texto_cifrado, TAMANHO_MAX_MENSAGEM);

    inteiro64 n = 0;
    inteiro64 d = 0;
    const char *depois_de_n = ler_numero(encontrar_valor(valor_chave, "n"), &n);
    const char *depois_de_d = ler_numero(encontrar_valor(valor_chave, "d"), &d);

    if (quantidade == (size_t)-1 || depois_de_n == NULL || depois_de_d == NULL || n == 0) {
        printf("{\"error\":\"entrada invalida\"}\n");
        return 1;
    }

    /* 4. Decifra os números. */
    size_t tamanho_mensagem = descriptografar(texto_cifrado, quantidade, n, d, mensagem);

    /* 5. Imprime o resultado como UMA linha JSON:  {"message":"texto"} */
    printf("{\"message\":\"");
    for (size_t i = 0; i < tamanho_mensagem; i++) {
        putchar(mensagem[i]);
    }
    printf("\"}\n");

    return 0;
}
