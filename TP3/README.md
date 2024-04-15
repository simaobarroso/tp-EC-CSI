
# TP3

Estes problemas destinam-se à criação de protótipos em Sagemath que implementem técnicas criptográficas pós-quânticas.


1. No capítulo 5 dos apontamentos é descrito o chamado Hidden Number Problem. No capítulo 8 dos apontamentos é discutida um artigo de  Nguyen & Shparlinsk , onde se propõem reduções do HNP a problemas difíceis em reticulados. Neste trabalho pretende-se construir, com a ajuda do Sagemath, uma implementação da solução discutida nos apontamentos para resolver o HNP com soluções aproximadas dos problemas em reticulados.


2. Em Agosto de 2023 a [NIST publicou um draf da norma FIPS203](https://www.dropbox.com/scl/fo/vllnz60fnd4payrkllm1d/h?dl=0&rlkey=4z7418pn17qcgmx97etxepvzo)  para um [Key Encapsulation Mechanism (KEM) derivado dos algoritmos KYBER](https://www.dropbox.com/scl/fo/y2i97mufz371tmz0orc40/h?rlkey=ffhdgacrx5wb4jsjb84kugclq&dl=0). 
    O preâmbulo do “draft” 
> A key-encapsulation mechanism (or KEM) is a set of algorithms that, under certain conditions, can be used by two parties to establish a shared secret key over a public channel. A shared secret key that is securely established using a KEM can then be used with symmetric-key cryptographic algorithms to perform basic tasks in secure communications, such as encryption and authentication. This standard specifes a key-encapsulation mechanism called ML-KEM. The security of ML-KEM is related to the computational diffculty of the so-called Module Learning with Errorsproblem. At present, ML-KEM is believed to be secure even against adversaries who possess a quantum computer


Neste trabalho pretende-se implementar em Sagemath um protótipo deste standard parametrizado de acordo com as variantes sugeridas na norma (512, 768 e 1024 bits de segurança)
