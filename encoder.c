/*
 * encoder.c - Criptografia RSA (Matemática Discreta - UFAL)
 *
 * O que o programa faz:
 *   1. Lê UMA linha JSON da entrada padrão (stdin), por exemplo:
 *        {"message":"Bom dia.","public_key":{"n":3233,"e":17}}
 *   2. Cifra cada caractere da mensagem com a chave pública (n, e).
 *   3. Imprime UMA linha JSON na saída padrão (stdout), por exemplo:
 *        {"ciphertext":[524,2185,2271]}
 *
 * A matemática (uma vez para cada caractere):
 *        m = código ASCII do caractere
 *        c = m^e mod n          <- o número cifrado
 *
 * Compilação:
 *   gcc -std=c11 -Wall -Wextra -Werror -O2 encoder.c -o encoder
 *
 * Ordem sugerida de leitura:
 *   main -> encriptar -> exponenciacao_modular -> multiplicacao_modular
 *   (as funções de leitura do JSON ficam por último: são só "encanamento").
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Nomes mais curtos para os tipos inteiros grandes que vamos usar. */
typedef unsigned long long inteiro64;   /* 64 bits: vai até ~1,8 * 10^19  */
typedef unsigned __int128  inteiro128;  /* 128 bits: guarda produtos de dois números de 64 bits */

/* Tamanhos dos "vetores" (arrays). A spec exige no mínimo 1000 caracteres. */
#define TAMANHO_MAX_ENTRADA   (1u << 20)   /* o JSON de entrada: 1 MiB      */
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
 * expoente é enorme), usamos os bits do expoente em binário.
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
/*  PARTE 2 - ENCRIPTAÇÃO (função com nome exigido pela spec)             */
/* ====================================================================== */

/*
 * Cifra cada caractere de 'mensagem' com a chave pública (n, e).
 *
 * Guarda os números cifrados em 'texto_cifrado', na mesma ordem dos
 * caracteres, e devolve quantos números foram gerados (um por caractere).
 */
static size_t encriptar(const char *mensagem, size_t tamanho,
                        inteiro64 n, inteiro64 e,
                        inteiro64 *texto_cifrado)
{
    for (size_t i = 0; i < tamanho; i++) {
        /* O cast para unsigned char garante um valor de 0 a 255 (o código ASCII). */
        inteiro64 codigo_ascii = (inteiro64)(unsigned char)mensagem[i];

        /* c = m^e mod n */
        texto_cifrado[i] = exponenciacao_modular(codigo_ascii, e, n);
    }
    return tamanho;
}


/* ====================================================================== */
/*  PARTE 3 - LEITURA DO JSON (só "encanamento", sem matemática)          */
/* ====================================================================== */
/*
 * Não usamos biblioteca de JSON. Como o formato é fixo e simples, basta
 * procurar o nome de cada campo no texto e ler o valor que vem depois.
 *
 * Limitação aceita pela spec: a mensagem NÃO contém aspas duplas (")
 * nem barra invertida (\), então não precisamos tratar essas "fugas".
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
 * Exemplo: em   {"n":3233,"e":17}   procurando "e" devolve um ponteiro para "17}".
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
 * Lê um texto entre aspas (ex.: "Bom dia.") que começa em 'p' e copia o
 * conteúdo, sem as aspas, para 'destino'. Devolve o tamanho do texto,
 * ou (size_t)-1 se algo estiver errado.
 */
static size_t ler_texto(const char *p, char *destino, size_t capacidade)
{
    if (*p != '"') {
        return (size_t)-1;
    }
    p++;                                  /* pula a aspa de abertura */

    size_t tamanho = 0;
    while (*p != '\0' && *p != '"') {
        if (tamanho >= capacidade) {
            return (size_t)-1;            /* mensagem grande demais */
        }
        destino[tamanho] = *p;
        tamanho++;
        p++;
    }

    if (*p != '"') {
        return (size_t)-1;                /* faltou a aspa de fechamento */
    }
    return tamanho;
}

/* Lê um número inteiro positivo que começa em 'p'. Devolve 1 se deu certo, 0 se não. */
static int ler_numero(const char *p, inteiro64 *valor)
{
    if (p == NULL || *p < '0' || *p > '9') {
        return 0;
    }
    char *fim;
    *valor = strtoull(p, &fim, 10);
    return 1;
}


/* ====================================================================== */
/*  PARTE 4 - MAIN                                                        */
/* ====================================================================== */

/* Ficam fora do main (static) porque são grandes demais para a pilha. */
static char       entrada[TAMANHO_MAX_ENTRADA];
static char       mensagem[TAMANHO_MAX_MENSAGEM];
static inteiro64  texto_cifrado[TAMANHO_MAX_MENSAGEM];

int main(void)
{
    /* 1. Lê tudo o que veio no stdin e termina o texto com '\0'. */
    size_t bytes_lidos = fread(entrada, 1, sizeof(entrada) - 1, stdin);
    entrada[bytes_lidos] = '\0';

    /* 2. Localiza os campos "message" e "public_key" no JSON. */
    const char *valor_mensagem = encontrar_valor(entrada, "message");
    const char *valor_chave    = encontrar_valor(entrada, "public_key");
    if (valor_mensagem == NULL || valor_chave == NULL) {
        printf("{\"error\":\"entrada invalida\"}\n");
        return 1;
    }

    /* 3. Extrai a mensagem e os números n e e (de dentro de "public_key"). */
    size_t tamanho_mensagem = ler_texto(valor_mensagem, mensagem, sizeof(mensagem));

    inteiro64 n = 0;
    inteiro64 e = 0;
    int leu_n = ler_numero(encontrar_valor(valor_chave, "n"), &n);
    int leu_e = ler_numero(encontrar_valor(valor_chave, "e"), &e);

    if (tamanho_mensagem == (size_t)-1 || !leu_n || !leu_e || n == 0) {
        printf("{\"error\":\"entrada invalida\"}\n");
        return 1;
    }

    /* 4. Cifra a mensagem. */
    size_t quantidade = encriptar(mensagem, tamanho_mensagem, n, e, texto_cifrado);

    /* 5. Imprime o resultado como UMA linha JSON:  {"ciphertext":[a,b,c]} */
    printf("{\"ciphertext\":[");
    for (size_t i = 0; i < quantidade; i++) {
        if (i > 0) {
            putchar(',');
        }
        printf("%llu", texto_cifrado[i]);
    }
    printf("]}\n");

    return 0;
}