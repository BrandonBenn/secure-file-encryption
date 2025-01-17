<h1 align="center">Secure File Encryption using TPM</h1>

Demonstrate using TPM module to encrypt and decrypt files on disk

<br/>

<h2 align="center">DESCRIPTION</h2>


```
+---------------------------------+
|          CPU / SoC              |   <-- Our Code
|                                 |        
|                                 |    
|  +---------------------------+  |   
|  | OS Driver / TPM Library  |   |   <-- Communicates with TPM over LPC or SPI bus
|  | (tpm2-tss)               |   |
|  +---------------------------+  |
+---------------------------------+
               |  SPI / LPC / I2C
               v
+---------------------------------+
|           TPM 2.0 Chip          |   <-- Discrete or integrated
| (Dedicated secure microprocessor|
|    + secure storage + RNG)      |
+---------------------------------+
```

References:
- https://tpm2-tss.readthedocs.io/en/latest/
- https://tpm2-tools.readthedocs.io/en/latest/INSTALL/
- https://advdownload.advantech.com/productfile/Downloadfile4/1-282ENXZ/How%20to%20initialize%20and%20simply%20test%20TPM%20in%20Linux_20220505.pdf
