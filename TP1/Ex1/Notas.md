# Notas para ex1

Alterar forma de funcionamento de nonce:

- deve ser gerado random pelo emissor a cada mensagem
- o recetor deve guardar o nonce e verificar se já foi usado
    - se já foi usado, rejeitar a mensagem

Alterar forma de funcionamento do programa:

- o emissor e recetor devem ser executados em simultâneo

Notas Simão:
Será melhor utilizar multiprocessing ou asyncio?
cython