# RSAES-OAEP (RFC 3447) Encryption Tool for H8S/2329 Family Embedded System
Less than 16Kb of code size.
## Assumptions:
According to the manual reference of the following document https://www.renesas.com/en-eu/document/hw-manual?hwLayerShowFlg=true&prdLayerId=113&layerName=H8S%252F2329&coronrService=document-prd-search&hwDocUrl=%2Fen-eu%2Fdoc%2Fproducts%2Fmpumcu%2F001%2Frej09b0220_h8s2329.pdf&hashKey=48c4c71aed4ab2d891bcfcd5ee20780a
- Supported 16 bit / 32 bit registers and memory allocations, but not 64.
- Big Endiand used (though it doesn't matter).
- C99 Supported by the compiler.
    * NOTE: the program doesn't support importing keys from PEM and DER format.
    * ATTENTION: this encryption is implemented according to RFC 3447 Section 7.1 (https://tools.ietf.org/html/rfc3447#section-7.1) (aka RSAES-OAEP without Signature)
    * However, It works correctly only with valid input (errors handling not managed yet).
    * So Make sure to always check your (key / input).

    /**
     * RSA arguments: N and e
     * we feed N in hex format, but it is not required for the encryption.
     * used key for the example (PEM format): 
        -----BEGIN RSA PRIVATE KEY-----
    MIIEogIBAAKCAQEA9Pj6wMGCL5DB/zW4F++kYla3DXfhKYJlOjdZhuRRJkPeJpWZstELZgKHvqWn
    PnaK5Iig19OKvv7MpfZZaL5qyqJEU9tGFL96GFu/1XMLV3CUSUkohndwECitZEwjT/+FKwxFNlGU
    e+OjWjSgfSc2+DyfEm9Q13Agz8N/kXmV2omp9WE0BmH8rxozJKwDrflg4kLmSN+5t8qLx83RjHWg
    DCAhI6kDKZCFne7o3hdFfV9x60NbGCdvgvfWXWr5ZrnzP5P9BxS4sxGQTaumiGa1knYqR8a39tyQ
    mjEjFJsBscch//qQe4d3hGIayOwKo/5PGFY2iQoP0yfY/eCjia20sQIDAQABAoIBAEAoZSPOilYC
    x4wbeZdrP9Yxd8ejOekxKWnRzTSy3z3yUGAylgprDV0uFHct01tcmIu57MYZtSDIgriEiG4SUM25
    KcP8jaIpc8SlYtx4QOQpq+x1qJNu/H5+6Mp31lfBSBM6J3ZOb2DzAXlChzW/63mgBtlBJh8GUtGX
    FfX3rfOJzzboecKZDh2g7mfyGKu9X0LIK7tpaGnbxaUERlcCwcXYtjeTDOvIACHsJeBI9Z7oCqtc
    tRWmDRDvATKbTNVD7Rlbfkrw2PdegmuHj3Y5LOmv5Pk1lXU2RR89xGNyNdgxpmnZhmcv/UxjbY0c
    7+3XKj/dILCEBj4SqYCpBo/2e3ECgYEA/SXI7yI9K14gpEsOSA8WbrdEJ+Q6iVgc/8WgfpWZD7Np
    78VVLqygTn0OYchcokFX6rrAxvquiFwRPzuo30Iou21b8Zale/ykdBLuWcS3LWgdQPRGmNwbOGBD
    df1lSq38bzTpSFBKIg8vYpFdXZjSVYcZo7bG9aK1kMe+ee9S/SsCgYEA97udCCvfXPCUMhDpyjW8
    TSWTFH0Hc4B87n63zdB750MEpPwbzVimxoWUG0XzlZMMVkcC1yM2ZseA9UA8ps/mFCAgL53J697S
    3PWu/x7WFcFGQgYVaPszBXSmcqppTSR+LPvevw9nB1uImchQfrTMR39ZFSdEQR2j3ZwN48lKf5MC
    gYAB5oK3qN4ksTQ1h4q358UXV7DfS8tUtKCjGuy1hpH7mDE3Z5fYHdumOzIccdCgNzVdwcEovUEK
    LQbEHsKJyolbvtpt2d+sKp1hcbLwYZWudZWiozLUevKJXc+j1x8njF7UxuTpchDcaJjGeKjmxvrt
    QXJj1D9yIKKUT6uSZsWMuQKBgC4xMWqgo5l00m0zciReOKo5417ioU0MHD9sKWGbCj9o46jPyW9U
    pGRH7AHZ3T16mcZMn172FeK8OHOCcsy33zLJerbmOQxeE/tXZDX1zf1oeG0/LSbSEAVoZtDirZfQ
    wiYpILOHb7KTgrkJ/NhjZeO+/yFOnQ93M2LTAlQC6H05AoGAZgxdgau13nQQIRMpUp8C++fa8BHj
    R0M+rFPzpmCKX+OgE9XvHV385TpGXp+4Ink17mAMWZzsEXpunZX+bCObRYztW9jobZOUxztKDTIW
    WLNthIoIo+e8QbV9lqQnLZv02cV2MG+nZkYa+vBR3ESP/CEge0OlEYVkKFsyH6Bw9aY=
    -----END RSA PRIVATE KEY-----

    */
  
  
  
  *FIXME:*
  - remove usuless code
  - improve error handling
  - PEM/DER support 
