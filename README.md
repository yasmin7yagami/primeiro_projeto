# trabalho-1-
trabalho das scripts 1 e 2 
import json
import os
from enum import Enum 

#----------------------------------------------------------------------------------------
# Enumeraçao dos tipos de ativos 
#----------------------------------------------------------------------------------------

class tiposdeativos(Enum):
   COMPUTADORES = 1 
   SERVIDOR = 2
   ROTEADOR = 3 
   SWITCH = 4
   IMPRESSORAS = 5
   BANCO_DE_DADOS = 6
   NUVEM = 7
   HARDWARE = 8

   @classmethod  
   def obter_codico(cls, codigo):
       for tipos in cls:
           if tipo.value == codigo
              return tipo
      return None 
      
