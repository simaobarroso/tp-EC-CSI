## Estruturas Criptográficas - Criptografica e Segurança da Informação

### TP2

Estes problemas destinam à iniciação do uso do SageMath  em protótipos de esquemas clássicos de chave pública.


1. Construir uma classe Python que implemente o  EdDSA a partir do “standard” [FIPS186-5](https://csrc.nist.gov/publications/detail/fips/186/5/draft)
    1. A implementação deve conter funções para assinar digitalmente e verificar a assinatura.
    2. A implementação da classe deve usar  uma das “Twisted Edwards Curves” definidas no standard e escolhida  na iniciação da classe: a curva  “edwards25519” ou “edwards448”.
| Consultar a diretoria  EcDSA para informação adicional sobre o RFC 8032 que propõe o standard para o esquema  EdDSA assim como os parâmetros das curvas “edwards25519” e  “edwards448”. |

2. Uma das aplicações mais importantes do teorema chinês dos restos (CRT) em criptografia é a transformada NTT “Number Theoretic Transform”.  Esta transformada é uma componente importantes de “standards” PQC  como o Kyber e o Dilithium mas também de outros algoritmos submetidos ao concurso NIST PQC.  A transformação NTT tem várias opções e aquela que está apresentada no +Capítulo 4:  Problemas Difíceis  usa o CRT.
    Neste problema pretende-se uma implementação Sagemath  do NTT-CRT tal como é descrito nesse documento.


3. O algoritmo de Boneh e Franklin (BF) discutido no +Capítulo 5b:  Curvas Elípticas e sua Aritmética é uma tecnica fundamental na chamada “Criptografia Orientada à Identidade”. Seguindo as orientações definidas nesse texto, pretende-se construir usando Sagemath uma classe Python que implemente este criptosistema.


| Note-se que o Sagemath tem definido curvas elíptica super-singulares, a  aritmética nessas curvas elípticas e os emparelhamentos de Tate. Todas essas componentes vão aparecer na definição do algoritmo BF. |
