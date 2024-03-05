
# [TP1](https://paper.dropbox.com/doc/Estruturas-Criptograficas-2023-2024-Trabalhos-Praticos-8WcsdZARGLv0nXS9KasmK#:uid=987745248868474781854548&h2=TP1)

Nesta pasta está contida a resolução do Grupo 3 do Trabalho Prático 1 da Unidade Curricular de Estruturas Criptográficas do Mestrado em Engenharia Informática da Universidade do Minho.

[Grupo 03](https://paper.dropbox.com/doc/Estruturas-Criptograficas-2023-2024-Trabalhos-Praticos-8WcsdZARGLv0nXS9KasmK)
| Número | Nome| 
|----------|----------|
| PG54177 | Ricardo Alves Oliveira | 
| PG54236 | Simão Oliveira Alvim Barroso| 

Enunciado :

1. Use a package Cryptography   e  o package ascon ([instalar daqui](https://pypi.org/project/ascon/)) para  criar um comunicação privada assíncrona em modo  [“Lightweight Cryptography”](https://csrc.nist.gov/projects/lightweight-cryptography) entre um agente Emitter e um agente Receiver que cubra os seguintes aspectos:
    1. Autenticação do criptograma e dos metadados (associated data) usando Ascon (ver implementação aqui(No site está a redirecionar para o sitio errado está para o pip install de cima)) em modo de cifra.
    2. As chaves de cifra, autenticação  e  os “nounces” são gerados por um gerador pseudo aleatório (PRG)  usando o Ascon em modo XOF. As diferentes chaves para inicialização do PRG são inputs do emissor e do receptor.
    3. Para implementar a comunicação cliente-servidor use o package python `asyncio`.


2. Use o “package” Cryptography para
    1. Implementar uma AEAD com “Tweakable Block Ciphers” conforme está descrito na última secção do texto [+Capítulo 1: Primitivas Criptográficas Básicas](https://paper.dropbox.com/doc/Capitulo-1-Primitivas-Criptograficas-Basicas-YAcE9VWuF88R2fmPyvKlx).  A cifra por blocos primitiva, usada para gerar a “tweakable block cipher”, é o AES-256 ou o ChaCha20.
    2. Use esta cifra para construir um canal privado de informação assíncrona com acordo de chaves feito com “X448 key exchange” e “Ed448 Signing&Verification” para autenticação  dos agentes. Deve incluir uma fase de confirmação da chave acordada.
