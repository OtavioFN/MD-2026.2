# Criptografia e Descriptografia RSA: Sob um olhar da Aritmética Modular

Projeto Final de **Matemática Discreta** — Instituto de Computação (IC), Universidade Federal de Alagoas (UFAL) — Semestre **2026.2** — Professor Bruno Pimentel.

O repositório contém dois programas em C, `encoder.c` e `decoder.c`, que cifram e decifram mensagens de texto com o algoritmo **RSA**. Cada programa lê **uma linha JSON** da entrada padrão (`stdin`) e imprime **uma linha JSON** na saída padrão (`stdout`), o que permite integrá-los a uma interface web ou a qualquer outro programa.

## Integrantes

- Gabriely Vitória da Silva Oliveira
- Narel Silva de Oliveira
- Otávio Fernandes de Oliveira
- Tiago Lima Silva Filho

## Estrutura do repositório

```
.
├── encoder.c    # cifra uma mensagem com a chave pública (n, e)
├── decoder.c    # decifra uma lista de números com a chave privada (n, d)
├── README.md
└── LICENSE
```

## Como o RSA funciona (resumo)

Escolhem-se dois primos distintos `p` e `q` e calculam-se:

```
n   = p * q
phi = (p - 1) * (q - 1)
e   : inteiro com 1 < e < phi e mdc(e, phi) = 1             (chave pública: n, e)
d   : inverso de e módulo phi, ou seja, e*d ≡ 1 (mod phi)   (chave privada: n, d)
```

Cada caractere da mensagem é convertido no seu código ASCII `m` e cifrado separadamente:

```
Encriptar:       c = m^e mod n
Descriptografar: m = c^d mod n
```

Isso funciona porque `(m^e)^d = m^(e*d) ≡ m (mod n)`. A segurança vem da dificuldade de fatorar `n` para descobrir `p`, `q` e, a partir deles, `d`.

## Requisitos

- Compilador **GCC de 64 bits** (os programas usam `unsigned __int128`).
- Linux, macOS, WSL no Windows, ou MSYS2/MinGW-w64 no Windows.
- Nenhuma biblioteca externa é necessária.

Instalação do GCC:

```bash
# Linux (Debian/Ubuntu)
sudo apt install build-essential

# macOS
xcode-select --install

# Windows: instale o MSYS2 (https://www.msys2.org) e, no terminal MinGW64:
pacman -S mingw-w64-x86_64-gcc
```

## Compilação

Cada arquivo é compilado separadamente, sem avisos, com as flags exigidas na especificação:

```bash
gcc -std=c11 -Wall -Wextra -Werror -O2 encoder.c -o encoder
gcc -std=c11 -Wall -Wextra -Werror -O2 decoder.c -o decoder
```

No Windows (MinGW), o resultado será `encoder.exe` e `decoder.exe`.

## Como usar

As chaves **não são geradas** pelos programas: `n`, `e` e `d` devem ser fornecidos na entrada.

### Encoder (cifrar)

Entrada (uma linha JSON):

```json
{"message":"Bom dia.","public_key":{"n":3233,"e":17}}
```

Saída (uma linha JSON, com um inteiro por caractere, na mesma ordem da mensagem):

```json
{"ciphertext":[524,2185,2271,1992,1773,3179,1632,2825]}
```

Comando:

```bash
echo '{"message":"Bom dia.","public_key":{"n":3233,"e":17}}' | ./encoder
```

### Decoder (decifrar)

Entrada:

```json
{"ciphertext":[524,2185,2271,1992,1773,3179,1632,2825],"private_key":{"n":3233,"d":2753}}
```

Saída:

```json
{"message":"Bom dia."}
```

Comando:

```bash
echo '{"ciphertext":[524,2185,2271,1992,1773,3179,1632,2825],"private_key":{"n":3233,"d":2753}}' | ./decoder
```

### No Windows (PowerShell)

```powershell
'{"message":"Bom dia.","public_key":{"n":3233,"e":17}}' | .\encoder.exe
```

### Usando um arquivo de entrada

Para mensagens longas, salve o JSON em um arquivo e redirecione:

```bash
./encoder < entrada.json
```

No PowerShell: `Get-Content entrada.json | .\encoder.exe`.

### Gerando as chaves

Os programas não geram chaves, então use qualquer ferramenta para obter `n`, `e` e `d`. Exemplo em Python (3.8 ou superior):

```python
p, q, e = 61, 53, 17          # p e q primos distintos; e coprimo de phi
n, phi = p * q, (p - 1) * (q - 1)
d = pow(e, -1, phi)           # inverso modular de e
print(n, e, d)                # 3233 17 2753
```

### Fluxo completo (exemplo)

Com `p = 61`, `q = 53`, `e = 17` (logo `n = 3233` e `d = 2753`):

```bash
echo '{"message":"A","public_key":{"n":3233,"e":17}}' | ./encoder
# {"ciphertext":[2790]}

echo '{"ciphertext":[2790],"private_key":{"n":3233,"d":2753}}' | ./decoder
# {"message":"A"}
```

Um exemplo com primos de 9 dígitos (`p = 999999937`, `q = 999999929`, `e = 65537`):

```bash
echo '{"message":"Oi, RSA!","public_key":{"n":999999866000004473,"e":65537}}' | ./encoder
# {"ciphertext":[190676473980030839,559140961800682700,333815752948903898,564316748795815442,987758929114614994,793061240396063909,840013186117996208,22586468755837207]}

echo '{"ciphertext":[190676473980030839,559140961800682700,333815752948903898,564316748795815442,987758929114614994,793061240396063909,840013186117996208,22586468755837207],"private_key":{"n":999999866000004473,"d":125806779051223553}}' | ./decoder
# {"message":"Oi, RSA!"}
```

### Entrada inválida

Se o JSON estiver incompleto ou malformado, o programa imprime uma linha de erro e termina com código de saída 1:

```bash
echo 'lixo' | ./encoder
# {"error":"entrada invalida"}
```

## Regras e limitações

- **Caracteres:** a mensagem usa a tabela ASCII de **32 (espaço) a 126 (`~`)**.
- **Aspas e barra invertida:** a mensagem **não deve conter** aspas duplas (`"`) nem barra invertida (`\`), pois o leitor de JSON é simplificado.
- **Primos:** `p` e `q` com **2 a 9 dígitos**, o que mantém `n` abaixo de aproximadamente 10^18.
- **Tamanho:** suporta mensagens com mais de 1.000 caracteres (até 65.536 caracteres).
- **Desempenho:** cada execução termina em poucos milissegundos.
- **Saída:** exatamente uma linha JSON; os programas não imprimem menus, logs nem criam arquivos.

## Como o código funciona por dentro

Os dois programas têm a mesma estrutura:

| Parte | O que faz |
|---|---|
| `multiplicacao_modular` | Calcula `(a * b) mod n` usando `unsigned __int128`, evitando estouro de 64 bits com `n` de até ~10^18 |
| `exponenciacao_modular` | Calcula `base^expoente mod n` por exponenciação rápida (*square-and-multiply*), com cerca de `log2(expoente)` passos |
| `encriptar` (encoder) | Aplica `c = m^e mod n` a cada caractere da mensagem |
| `descriptografar` (decoder) | Aplica `m = c^d mod n` a cada número e converte o resultado de volta em caractere |
| Leitura do JSON | Funções simples que localizam cada campo e extraem texto, números e a lista `ciphertext`, sem biblioteca externa |
| `main` | Lê o JSON do `stdin`, chama `encriptar` ou `descriptografar` e imprime o resultado em `stdout` |

## Licença

Distribuído sob a licença MIT. Veja o arquivo [LICENSE](LICENSE).