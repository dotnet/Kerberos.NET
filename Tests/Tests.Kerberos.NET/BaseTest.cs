using Kerberos.NET;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Tests.Kerberos.NET
{
    public abstract class BaseTest
    {
        public const ValidationActions DefaultActions
            = ValidationActions.All & (~(ValidationActions.EndTime | ValidationActions.StartTime | ValidationActions.TokenWindow | ValidationActions.RenewTill));

        public const string RC4Header = "Negotiate YIIKbQYGKwYBBQUCoIIKYTCCCl2gMDAuBgkqhkiC9xIBAgIGCSqGSIb3EgECAgYKKw" +
            "YBBAGCNwICHgYKKwYBBAGCNwICCqKCCicEggojYIIKHwYJKoZIhvcSAQICAQBuggoOMIIKCqADAgEFoQMCAQ6iBwMFACAAAACjggiCYYI" +
            "IfjCCCHqgAwIBBaEaGxhJREVOVElUWUlOVEVSVkVOVElPTi5DT02iLTAroAMCAQKhJDAiGwRIVFRQGxphYWRnLndpbmRvd3MubmV0Lm5z" +
            "YXRjLm5ldKOCCCYwgggioAMCARehAwIBA6KCCBQEgggQj3u9OmvRqFMcpNQPVGL9GfXyt8uQXlMLzghXxhl6mLVqYSS6CwGoXwcGKqiDR" +
            "Xb1mll5br+naBy0ckhlnPN3LQmUNnEEk3rIOqHhKZYctiZ1QhVwatjBJ2yiEloGq+W4sl/IhHXH66y8I2mHLsuybiYodd9cUy4scQTx1S" +
            "1HSFTqc7x0HyHillie/rv/oO5MBXld1kxvaKoKIQ34qZXLRBJhSD9nrEbBhlFY3vMYMgOFf3Jnz9AH23c/N9Sj82l3TbEBPxnBp7zn3Fh" +
            "SreghloZqxDcCbe82pUI5tdX6AIylDDprCs3fJBYvxQZG5w0IYoqJBi2T9YvBzaVH2qxTG59GDIzZ/1yL2Ux16XwrezATDZAc9Exr98ep" +
            "pGRqidw8oo2/wjsz92ye56BHCYN/i+F6IvuXaqTfWPYKI9Vw5xvnUodvy7SJJs+mxDAdShPyqYkI/rYbJyjECffdCBRDwuLnp6OsPdtRU" +
            "pUC6uGBAtg6Zu9VYMGqJQV547em9pIuKHSd7Du4WYI1xdjIp/W2L8MFlAtJiC6YfPI7Z8e/7lXI3L0AFOOj5Tdp30q5oR3uigyGyPJVI5" +
            "WQb656g+bwadM0V43WYWhmOwsiZa/RH18C3XEWbEu/XhArZkvkxn47bKC7ypwl88ZzNJ5MiBJoegw6DD6iFdmAI1C7dQ0ku2Et/lj1iev" +
            "zMqW7I5OGwcaD0kWu/FcNK9L/lPkiCwUImtFeIxgKiZt+fOEu8HCHnayI1CpM5Cnv0ultprP97ntsswRQSyoHfz/boO8dS7xz2CeRbJ+y" +
            "Qh5Eqk5vEyX/ojpZcthzxQ05xNJ1z+v2LWwnrWQ4PNffC0EIBlV27+EZxEbylrh91waWII5xtlvKfpqez/Qg9WH4SCrjwHq1vlXPnGqd5" +
            "zDMobSA49vHOOkLiNuMd+EyB0OPQICkwCAO+Lq92hJtdkbIL+gjbCOzFEP6njlVDWNdwPodxeAvia0agaLnOuHanu8SAyyiMUQJLLWzRe" +
            "TbVePYbOLzFXZgotvgaBBjZQeL0fjDpfWgKLDPxqhIm7Ec6Tbj5g0o5IN+mHcvUfwfPXpxPst22+vzgSVzKnb02i/DhscOVbaI38r/f92" +
            "C93X2WlO58Yyad/PlJL8WBvXWMjblMKQiCgS82PsrpQki1l4K+by0Xw4UpcbzAx4PVlALJ3DzkmT4rLqbCC4ruaoCCp2nHFgx+KxMZmzU" +
            "3QtCZ8IQ0G8LNRnkW70FNNUnKoMkmz4Qp6kum4XRO+mcvDJ7oYxZmETZShb2DMsstxpbxyaNvO0uuoT4lgn3dQTiE1W9Vh2ieeONOX/nx" +
            "74YBfL7lnW+mlSsi2bXxK8iGzPbNp11LXhn1pNSTJyo2cOKp6McBdZSy8wi8BVICxncXXd5NcWEqDPs61+CJGTHZrwHTulnLLAPW624xS" +
            "56DKwai3OM668pOITuYnuRjppMic3kgQbsqh/JeWsti+PEll1+jxcpXp3YECumxUN6LDV34L79v8d/GlkSDbyK1kkzmnPkVdP1K/EYvPZ" +
            "logfBHe/D6RtRWge+BttVwQ/dAZRi7tyxSSJWtA4el6W6c2OxSpDgEQ6GBOFAyF/uZHqSrtVpMIaNPtZntqowiz7BSn84ZEb8/umTc2OS" +
            "PpTi/aNdIu2np3J7XRVKgX6+szvCjkQlLTAmugDRTQ9JjSw9LTUeUOgWtzZ+IJxY0g46cZQdZf154YDd1USIT1P0rjlR8eSbEHdovCLpP" +
            "5ADwd6ybklgHUVDDm50pBCVqPJVgEclGnIMbPOsErDDW9SqrCeUfwxC7EAF+J0xKbCjTkgc92wO4VbxZJKnW5z34RPt9anj73fdrKBKW/" +
            "6uMVi+D9XnNnyOVV5kgbV26O9+r4zBcpTR+5GPh+/FE0gyCcMKsKhfjQBdn5T33ULAxCe2hESD0rcJJWf9SCev2N/q4lE6Fm5hFPZjCQw" +
            "d4aUnDeadEvdJGklj08IGbpacQYP2eKQr1xYDRCg5iFYm51Q9ylRXHzPDhNBK4w4w9RkIFUjVIZkfmR/xJ87vBzSKzw8Qt4+yGCQyoSIv" +
            "i/QY9QOmm76IRJw1O2yzFRipWn/4EciQ/p+NI3UaUEJe02n5dx0pqaBDKcze6NuARQ48lAzfMNT+OJBoFUl/JZi9TxB/987FyozmR9vvT" +
            "HagM9hNz/pdmijur2EvJmBOYSPXridV1xwTQ4kJssWkFbV+17UPROStaVbsDj1rsyM5jMQhllPCsyzRKpOUVucriTSgKVGHXqo7tD6q+o" +
            "OR4Kmv7//rdSvRmh7gMTKjNsaopolOJUC9BWNLvlJnHFOcp435KfgUz4cV4mwAx9IqkNSJk/bOawvfujqyWVWBWkQ37cRbDO1Hbozd6FT" +
            "D/LTo1DEhi59+hCBWvxJXXSnDegBuuLXd7BYeXEmSZbedJlwyzACevSO8FDNx8AZ4XH8U6SQajiNrIOjv53tUe2cXwaCclAf/vMEeOqTh" +
            "07q5Ge9XrzaKqmZGBkJ2DaddJ5yqCaHr2guMCjIVkrdTeT6M3iS5pVQILVUTAfRMlC9cAT5pNm2FLgk9kz8lTyp24tXVkcq80ihAarQDf" +
            "8iSRmCQJswknV46VRebGE+MzWWoO/n8GLe5pCwa9Kluwl0rAADOS1KmUBOEySfq5KjzD1KiX1S/gqvdZ1VdDErP0jGbBFg8gIEXYTO2Rn" +
            "hzwi3OuCqrNbKyIDtI+0PfBk0q/mf3TalaMBUpHTlDRsoy+KPItEE5htaIL+AB8xD9pIIBbTCCAWmgAwIBF6KCAWAEggFctFqM6qfEqPs" +
            "Gt0rJWeIFCeZJvVxCgyBMXT1NDApntPaBPQSI/r3RCNnOCyJ4uk46xD2uALdozuRfw4u7D9xWksYiGLTKSohNWIKmmUiPb7JCuuaHKk3o" +
            "8HNfHZANRcr/nY2HDx9dMopF2xouf+D8q4jZIVKOKvsUQRW9WzVhi66aA5LJVNY7TseRyX6ijOdHEVMSo7jl510YCLNtIica699y6SGZH" +
            "OoH4ZwMJVT7yXrOV2Y45VXz/zHU+s5+l5g1ZQBUzsqF97s2dZ+lgWvoKFa4oeXIhz0ScAZoch8cFYz6ANKqVXgWcwn1F6ZC+Bg4Wg59FI" +
            "SOBsLlSWVcbntYUvV4q2vXE8+hl8ee47gEfJavtewr6fZ1ZVKbKx30Nsq4uR016qgZTVn4E0N86HP5G7qAOunSWZTf6sqgO5EC7arj0mi" +
            "0BJbdXywf0XZfdL+T0IX9kiIrADgK3e8K";

        public const string RC4Ticket_Claims = "YIIKbQYGKwYBBQUCoIIKYTCCCl2gMDAuBgkqhkiC9xIBAgIGCSqGSIb3EgECAgYKKwYBBAGCNwICHgYKKwY" +
            "BBAGCNwICCqKCCicEggojYIIKHwYJKoZIhvcSAQICAQBuggoOMIIKCqADAgEFoQMCAQ6iBwMFACAAAACjggiCYYIIfjCCCHqgAwIBBaEaGxhJREVOVElUWU" +
            "lOVEVSVkVOVElPTi5DT02iLTAroAMCAQKhJDAiGwRIVFRQGxphYWRnLndpbmRvd3MubmV0Lm5zYXRjLm5ldKOCCCYwgggioAMCARehAwIBA6KCCBQEgggQj" +
            "3u9OmvRqFMcpNQPVGL9GfXyt8uQXlMLzghXxhl6mLVqYSS6CwGoXwcGKqiDRXb1mll5br+naBy0ckhlnPN3LQmUNnEEk3rIOqHhKZYctiZ1QhVwatjBJ2yi" +
            "EloGq+W4sl/IhHXH66y8I2mHLsuybiYodd9cUy4scQTx1S1HSFTqc7x0HyHillie/rv/oO5MBXld1kxvaKoKIQ34qZXLRBJhSD9nrEbBhlFY3vMYMgOFf3J" +
            "nz9AH23c/N9Sj82l3TbEBPxnBp7zn3FhSreghloZqxDcCbe82pUI5tdX6AIylDDprCs3fJBYvxQZG5w0IYoqJBi2T9YvBzaVH2qxTG59GDIzZ/1yL2Ux16X" +
            "wrezATDZAc9Exr98eppGRqidw8oo2/wjsz92ye56BHCYN/i+F6IvuXaqTfWPYKI9Vw5xvnUodvy7SJJs+mxDAdShPyqYkI/rYbJyjECffdCBRDwuLnp6OsP" +
            "dtRUpUC6uGBAtg6Zu9VYMGqJQV547em9pIuKHSd7Du4WYI1xdjIp/W2L8MFlAtJiC6YfPI7Z8e/7lXI3L0AFOOj5Tdp30q5oR3uigyGyPJVI5WQb656g+bw" +
            "adM0V43WYWhmOwsiZa/RH18C3XEWbEu/XhArZkvkxn47bKC7ypwl88ZzNJ5MiBJoegw6DD6iFdmAI1C7dQ0ku2Et/lj1ievzMqW7I5OGwcaD0kWu/FcNK9L" +
            "/lPkiCwUImtFeIxgKiZt+fOEu8HCHnayI1CpM5Cnv0ultprP97ntsswRQSyoHfz/boO8dS7xz2CeRbJ+yQh5Eqk5vEyX/ojpZcthzxQ05xNJ1z+v2LWwnrW" +
            "Q4PNffC0EIBlV27+EZxEbylrh91waWII5xtlvKfpqez/Qg9WH4SCrjwHq1vlXPnGqd5zDMobSA49vHOOkLiNuMd+EyB0OPQICkwCAO+Lq92hJtdkbIL+gjb" +
            "COzFEP6njlVDWNdwPodxeAvia0agaLnOuHanu8SAyyiMUQJLLWzReTbVePYbOLzFXZgotvgaBBjZQeL0fjDpfWgKLDPxqhIm7Ec6Tbj5g0o5IN+mHcvUfwf" +
            "PXpxPst22+vzgSVzKnb02i/DhscOVbaI38r/f92C93X2WlO58Yyad/PlJL8WBvXWMjblMKQiCgS82PsrpQki1l4K+by0Xw4UpcbzAx4PVlALJ3DzkmT4rLq" +
            "bCC4ruaoCCp2nHFgx+KxMZmzU3QtCZ8IQ0G8LNRnkW70FNNUnKoMkmz4Qp6kum4XRO+mcvDJ7oYxZmETZShb2DMsstxpbxyaNvO0uuoT4lgn3dQTiE1W9Vh" +
            "2ieeONOX/nx74YBfL7lnW+mlSsi2bXxK8iGzPbNp11LXhn1pNSTJyo2cOKp6McBdZSy8wi8BVICxncXXd5NcWEqDPs61+CJGTHZrwHTulnLLAPW624xS56D" +
            "Kwai3OM668pOITuYnuRjppMic3kgQbsqh/JeWsti+PEll1+jxcpXp3YECumxUN6LDV34L79v8d/GlkSDbyK1kkzmnPkVdP1K/EYvPZlogfBHe/D6RtRWge+" +
            "BttVwQ/dAZRi7tyxSSJWtA4el6W6c2OxSpDgEQ6GBOFAyF/uZHqSrtVpMIaNPtZntqowiz7BSn84ZEb8/umTc2OSPpTi/aNdIu2np3J7XRVKgX6+szvCjkQ" +
            "lLTAmugDRTQ9JjSw9LTUeUOgWtzZ+IJxY0g46cZQdZf154YDd1USIT1P0rjlR8eSbEHdovCLpP5ADwd6ybklgHUVDDm50pBCVqPJVgEclGnIMbPOsErDDW9" +
            "SqrCeUfwxC7EAF+J0xKbCjTkgc92wO4VbxZJKnW5z34RPt9anj73fdrKBKW/6uMVi+D9XnNnyOVV5kgbV26O9+r4zBcpTR+5GPh+/FE0gyCcMKsKhfjQBdn" +
            "5T33ULAxCe2hESD0rcJJWf9SCev2N/q4lE6Fm5hFPZjCQwd4aUnDeadEvdJGklj08IGbpacQYP2eKQr1xYDRCg5iFYm51Q9ylRXHzPDhNBK4w4w9RkIFUjV" +
            "IZkfmR/xJ87vBzSKzw8Qt4+yGCQyoSIvi/QY9QOmm76IRJw1O2yzFRipWn/4EciQ/p+NI3UaUEJe02n5dx0pqaBDKcze6NuARQ48lAzfMNT+OJBoFUl/JZi" +
            "9TxB/987FyozmR9vvTHagM9hNz/pdmijur2EvJmBOYSPXridV1xwTQ4kJssWkFbV+17UPROStaVbsDj1rsyM5jMQhllPCsyzRKpOUVucriTSgKVGHXqo7tD" +
            "6q+oOR4Kmv7//rdSvRmh7gMTKjNsaopolOJUC9BWNLvlJnHFOcp435KfgUz4cV4mwAx9IqkNSJk/bOawvfujqyWVWBWkQ37cRbDO1Hbozd6FTD/LTo1DEhi" +
            "59+hCBWvxJXXSnDegBuuLXd7BYeXEmSZbedJlwyzACevSO8FDNx8AZ4XH8U6SQajiNrIOjv53tUe2cXwaCclAf/vMEeOqTh07q5Ge9XrzaKqmZGBkJ2Dadd" +
            "J5yqCaHr2guMCjIVkrdTeT6M3iS5pVQILVUTAfRMlC9cAT5pNm2FLgk9kz8lTyp24tXVkcq80ihAarQDf8iSRmCQJswknV46VRebGE+MzWWoO/n8GLe5pCw" +
            "a9Kluwl0rAADOS1KmUBOEySfq5KjzD1KiX1S/gqvdZ1VdDErP0jGbBFg8gIEXYTO2Rnhzwi3OuCqrNbKyIDtI+0PfBk0q/mf3TalaMBUpHTlDRsoy+KPItE" +
            "E5htaIL+AB8xD9pIIBbTCCAWmgAwIBF6KCAWAEggFctFqM6qfEqPsGt0rJWeIFCeZJvVxCgyBMXT1NDApntPaBPQSI/r3RCNnOCyJ4uk46xD2uALdozuRfw" +
            "4u7D9xWksYiGLTKSohNWIKmmUiPb7JCuuaHKk3o8HNfHZANRcr/nY2HDx9dMopF2xouf+D8q4jZIVKOKvsUQRW9WzVhi66aA5LJVNY7TseRyX6ijOdHEVMS" +
            "o7jl510YCLNtIica699y6SGZHOoH4ZwMJVT7yXrOV2Y45VXz/zHU+s5+l5g1ZQBUzsqF97s2dZ+lgWvoKFa4oeXIhz0ScAZoch8cFYz6ANKqVXgWcwn1F6Z" +
            "C+Bg4Wg59FISOBsLlSWVcbntYUvV4q2vXE8+hl8ee47gEfJavtewr6fZ1ZVKbKx30Nsq4uR016qgZTVn4E0N86HP5G7qAOunSWZTf6sqgO5EC7arj0mi0BJ" +
            "bdXywf0XZfdL+T0IX9kiIrADgK3e8K";

        public const string TicketContainingDelegation = "YIIN3gYGKwYBBQUCoIIN0jCCDc6gMDAuBgkqhkiC9xIBAgIGCSqGSIb3EgECAgYKKwYBBAGCNwICHgYKKwYBBAGCNwICCq" +
            "KCDZgEgg2UYIINkAYJKoZIhvcSAQICAQBugg1/MIINe6ADAgEFoQMCAQ6iBwMFACAAAACjggVLYYIFRzCCBUOgAwIBBaEfGx1DT1JQLklERU5USVRZSU5URVJWRU5USU9OLkNPTaI0MD" +
            "KgAwIBAqErMCkbBGhvc3QbIWFwcC5jb3JwLmlkZW50aXR5aW50ZXJ2ZW50aW9uLmNvbaOCBOMwggTfoAMCARehAwIBA6KCBNEEggTNYb+bd5txM65Saj1CDgQqRXlbBPHPGAlwjZYIQe" +
            "KQCk1GU/eXthXiOPgBESM10io9mhBY8cKFXXTxUCYSWpd2z1XQx+FRvuSS/E2MC4jNgcarnJKpLdjDOkvAakQ61OC2S+Sy/9VBxRcy8UHlk9OQxxxsf4ut46sGi68WJIUnM6aN/yvZK1" +
            "Thm0qW7ygJcOKkLBqyoCrddBv0bpiCuX1QCuwAWQ2axn0L3okIwpdmVHeBaHuToieunT2R4QBsAC1VxVbhSDIlWJXF/Y//goL0Wr9jWtP58AixpykRPBBNIcPlpq5RWXbBYIlhypd7hP" +
            "t/rua3bCSM9SdEfIu1Qhjou1Kebe00a7CnsEjCJaDN+AArigV/4gqdDb1M/T3qP2SerzX2qmjHME/w4vULBfczpqFCcITrN1c60C0rbwU+6CGAXZW+k8qnvGThh0Xm6q7z4y0vU+aK3V" +
            "1tMrrtg9a3VXqHZNFlH33tUcBd9PvQEGySOq2xzE4NHEH5D62LbxkA9Y5siupyiIR08wVdAhfAIzHAj+mWk742raLbFsCgvSi2BQHnb8aKJg5clChMV9JgIkhXvSc/H7lxLPvWCSRoJn" +
            "lNn8/c3eObRPhabyS8mTZUnA8//qtPI+ZRyfwee2U0pWo4kCo0QodpTwFVAh+m0RE5tKFYwWtCXrOdLmdmoFYfmUEJDxYPVQnfZncKBs/m5duX5JBrADMhP5ErwHUqzAjotTMUlP7L9b" +
            "XS+cCeuQNX9r7kkA5aK0Z+O/gzdM+CQ1kWnNHNEp8cd+pRgI5txYFBj+3IM3Z1fRyAvw0pSr9rGEnFU5dyL/3WX+gVX3V2PIkdr5qLoOvwC02n3xn7FSTFgfzZFOq9KxBRibCoWqdsdf" +
            "lC4OILUumcFnw9dQCa6KhptOegyQi6KaWFZaviLRiyuGoniVpNTm46KvH0up7wdlSKH3a5emHcfYdsbMur32FiOLGQjNDP+/WZjlbVWC34eTsNKaDrzF9QV3z3YPwdenUr5pGBQtAPuL" +
            "t06/BVECt9tiNCKjueWhZ18dSkD+XusU3AUl+y5hR8L5ZYe5GbPA/oatyGRl4uQgmN2CdjB3UQh3Mbud1CWCmorYAyVKCWuz6Jzffk4oomKS3ptMDz3tmZ5Qt6YESMv0xmwwrnxmkS0e" +
            "Xn6DJevW18nCqTwLJo7/VyDnkQeIKWKGrYmZG8dU1D+w/0tT01IZyTKR3z41DlhQQyfF6mfs5qjQP3WaIizN1EPY5iRfr6KQ16LjreO2ngOD6YQc/HxEMJupAyi+JkK6Ig+cN/R5avoY" +
            "MDE5oqhGsXDhGl84E1uTB8dwME5gQifMJIk1U6zvaP5gtZIAKkfRw1KPfnlF+V60Ok2aL+ZF9ra+8PC4MSnZNfwhFOZBowCSTE9Ba0eV2ciO2SR3vvEXUQ6vo8c5Hn49MdCW7dp9YmII" +
            "cG8DrjuiNHnKM2zRLAk3Nt3mPwLSmqPeoTyCLjdM9aYVjYWOhJvdilNoUws2VRF3QsbLSZZepMc74ywD2lcVPCZcd2ujXVfTze9o/oH+RtEBHkOkAZ/5/pQnnthmKsH3deFvmCJMGuGU" +
            "Sikjjy3wyyyXChdOxt0Qp+5gxrsO/5Lfnw42U1DPIals8hfZVZ6An9g8WZ+pqkgggVMIIIEaADAgEXooIICASCCASiSdnOwSoc8GJlGvuAZ46vrGv1a0FcYx1UcgqZx5Iaxn0BmUnWfX" +
            "bxji6aMdP8YA+TPoz0R4cfWAEBykwaQ/Xm+5kcL0JbjBDGRFV5iMXN8kb1YYdZ904IzlnXSbhNzyw1NyMAx0A8d/HjoHo5vTMEdx3OwdrfhYGKtnYSYPXo2oF4YxSD9GiJwbHD7EExTa" +
            "eOGRVDXEGbM/hoUe6LjketuXOErfDhjW6LK8MpTryRGriPM4ovyuoWTTXGlltkiuun5wjqtXc5nkTWeSWkYkPz5+JFWwsGM67twE+2xLHOZqqyw5bHuk5qZ77ikiIZa+Nbg2kPSZwBJ8" +
            "mPLRJ28f4UiWh2VWTQT2AhvubalWeyOkEKam4RMJBiT4uc8nIkDRdHursczloSiLJqMgOg0cVHVmGRelYaWKmMLHwZvwlLjEBdM6didf2eK0L7fKwLGLkSFWojCzl619NzSOYpqPF4aU" +
            "BSNVurCuOLGBNdwDgGOKFjtRNWyc/7Nnlq2vsYr8fXYcavSQgjvv6T/7WSoNODf/RLDtNQPBO9Qu49t9Hh8XeJAHQmrVoj3IMO5A7HnQuDhXl9mCOKEuMNKLTd4u9qTJwej3yaiCqPLB" +
            "+UbTHUthqqX0v/huiBmdsm/mFddfVrjAWcuHctB8K5rFzyJ5KJ+5rhp0lWFGQcATO8FoSO75ZBoo4fprxXFDCP4msUBXkpYr4UPN8gHMis4LtRcq4rGQF99DMHNf9zM7Yl//H5sW0qEU" +
            "SuV8lnnfiLnXiEI/QDJqkgLWzv5FyAH40eVZA90UCX/14lDokuoYX3RsMAmhbI/FW/B/E+JNOhwSKGpzpgnDYaUJ48X6rEBv7bFFD5ugMiIObZOynaLaGzy8X9urftO29+81MtqiKSLq" +
            "eTiYctOIIaGAxhf9MojcMc48ML4tj7t6t/wtj61iZhysctT6tYBPNXvgzMcaAGglDskrnkUVS4I2p9L1VxIqfZTIQRJnaGrVrWbZge4xovnocFdTra9ENRezCRwXJpy6EpUfIuQl0nn5" +
            "fcXgKTi6sS2hTlvExj+TVzTTU64TF6S9mxdJIno1HOK8oZ4r+M6HmcFq6f5F2jn+oDsyEiZvZjO7GJRYieir51xGVLH/YNFu3gzYBuEfQzu7SxvjL23mRGlLxe//1TcrgaK24vybR09U" +
            "7bVc2hleqtRZEvDfNgFGR2fasEMEOhhLQlhalv1c+gPQiUMs1CX1LhOeU8fktlybHCoE6blXhVLAigun3wdPYm9tB0YJPortQUtbemRtpM8g+WP0RwaCykn669crblCxbCdC63WXYJcW" +
            "oRF41dZ55meHUsFHLpNgcOeoNBfvEByvMz9cjJT40C1/nykBwHMDX23IS3RU1hUU/c1I9lqQDVfw14QeDSW2Br5fd461dMo6rzrRJ5mfpQ5CHcljLkz61oViBY0E+qOK1IDPjg2rCjw2" +
            "8bhjdkWrePKAS8wb6OuXfUAwbJnzzwJrb48ZzYFZqUxS41jjsQAdelRdiEZp0550MuYA/iWPcWkpNFEvVtkRMgAbPllMv0WA1pl3mwpcA5gRVvFeZWHTVH0ncfLQ8ghAfZkEV8yVtbox" +
            "/ZM6MbsIN3VuGs4DAc8GdKGGZAB5eKA0rALiRhb4vHD/iUhIJlGL+7sI3aWSvG1cq9cpMg0QsKBkiSljGKxoPMXLFKwmmLTw8PXe/whnc55QH6bR62SbDJWwwM0WzeEVL9p2WWrNTGvH" +
            "ESD8cgQU3RltmGvJ1bakRS3cqK4SrPhWPJxhRacTVnbCvXo/zT38aUeNK4Ro3gsJS1EFM6Lptn27V6MJUXhg7m7B+C5WQTOW9QWmdRCBzm46Ye3NZ8QycVHwJRQTIDdLLlAa6L3isMfQ" +
            "9f54IaITpto2ImTR6lJLEfNYxWbezX0qpvVJhWZ2Ne5klvyWCf+bhM163lmAMZv5onJZkKQuxZdA6JmVpiWdiDoAa5Th/Vn/aZaqyoXeCXTsy5i2h1NsoSD7qxN+FW0EGYX3SbHWVDIt" +
            "u9umZeBza6TFgiczx62v48foqYlNS9TYhMF19zldTRtnF2DCid/FOAFMw2PAXHrL0nFA8lTIafWTHFnmX60xA+pwzXsm9hNNefRK2vSUYkFZE5fegK4NN96dTX7kaAudLs3PGPpw5g5J" +
            "BZSGzPAkBVQZYg1dAeQhyKfkn69+hQFMca75hImY1yEx/1paXmel1KmtQjZIgkg+KWEzrFtwUFiHABI2sIS1nDYRwAyVo5HZ1/z/TMVC1zd9Dn0cdRcE8UM5Og1bjES5NE9Jc/Lvgbcu" +
            "PbBAF22IQM73NmZ19wu9zFhKja5Ly7V+P2785fel9YxqdC3vcgM8IaX1RLsxyZyc8H5VYB6Eb2oUJnkDwTLmTtmO32LM322Y3yoU0ZdnP4z0FIEEvW5SO+V7lQcnGrrPqgkxctyaGPMD" +
            "w4vA6I0ib2hn2+yLW3D3w2QMLx4aaW2U2FwzU+aHvbpyMqDx4Fw72eaeEhDXwQGGelSwSh10V6MbL92uPgSERWCKGaG0bRKJ21ZIw2aTo7DK06osv4qsV5QGrWMQVqylWWg7i4JBaXOU" +
            "AFffP2PNqYn95dA4HD/On0QpOkNykZ3JBzSLnEr0+lo7bgZOTAF5m1IBwwEMdMhZRYudg4/MRPgKSzAx2cDfFfqe3c5a/e8IjYdZHI3fmQa1rPXn5XQ03aw9YJNkW1VNb0+n5JGR4Jge" +
            "C12oQyIh4DSu3XGvlXi+swg90=";

        private static readonly string BasePath = $"data{Path.DirectorySeparatorChar}";

        protected static byte[] ReadDataFile(string name)
        {
            return File.ReadAllBytes($"{BasePath}{name}");
        }

        protected static Dictionary<string, byte[]> ReadDataFiles(string path)
        {
            var files = Directory.GetFiles($"{BasePath}{path}");

            return files.ToDictionary(f => f, f => File.ReadAllBytes(f));
        }
    }
}