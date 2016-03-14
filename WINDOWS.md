# Windows support

`Makefile.nmake` is a basic nmake-format makefile which builds the tests:

```
H:\src\fastpbkdf2>nmake -f Makefile.nmake

Microsoft (R) Program Maintenance Utility Version 14.00.23026.0
Copyright (C) Microsoft Corporation.  All rights reserved.

        cl /Iopenssl\include /O2 /W4 /WX /nologo  /c testfastpbkdf2.c fastpbkdf2.c
testfastpbkdf2.c
fastpbkdf2.c
Generating Code...
        cl /Iopenssl\include /O2 /W4 /WX /nologo  testfastpbkdf2.obj fastpbkdf2.obj /link openssl\lib\libeay32.lib
        cl /Iopenssl\include /O2 /W4 /WX /nologo  /c bench.c
bench.c
        cl /Iopenssl\include /O2 /W4 /WX /nologo  bench.obj fastpbkdf2.obj /link openssl\lib\libeay32.lib
        cl /Iopenssl\include /O2 /W4 /WX /nologo  /c benchmulti.c
benchmulti.c
        cl /Iopenssl\include /O2 /W4 /WX /nologo  benchmulti.obj fastpbkdf2.obj /link openssl\lib\libeay32.lib
```

and can run them:

```
H:\src\fastpbkdf2>nmake -f Makefile.nmake test

Microsoft (R) Program Maintenance Utility Version 14.00.23026.0
Copyright (C) Microsoft Corporation.  All rights reserved.

        testfastpbkdf2.exe
sha1 (6 tests):
expect: 0c60c80f961f0e71f3a9b524af6012062fe037a6
got   : 0c60c80f961f0e71f3a9b524af6012062fe037a6
- test passed
expect: ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957
got   : ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957
- test passed
expect: 4b007901b765489abead49d926f721d065a429c1
got   : 4b007901b765489abead49d926f721d065a429c1
- test passed
expect: eefe3d61cd4da4e4e9945b3d6ba2158c2634e984
got   : eefe3d61cd4da4e4e9945b3d6ba2158c2634e984
- test passed
expect: 3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038
got   : 3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038
- test passed
expect: 56fa6aa75548099dcc37d7f03425e0c3
got   : 56fa6aa75548099dcc37d7f03425e0c3
- test passed
ok
sha256 (9 tests):
expect: 55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783
got   : 55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783
- test passed
expect: 4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d
got   : 4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d
- test passed
expect: 120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b
got   : 120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b
- test passed
expect: ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43
got   : ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43
- test passed
expect: c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a
got   : c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a
- test passed
expect: 348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9
got   : 348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9
- test passed
expect: 9e83f279c040f2a11aa4a02b24c418f2d3cb39560c9627fa4f47e3bcc2897c3d
got   : 9e83f279c040f2a11aa4a02b24c418f2d3cb39560c9627fa4f47e3bcc2897c3d
- test passed
expect: ea5808411eb0c7e830deab55096cee582761e22a9bc034e3ece925225b07bf46
got   : ea5808411eb0c7e830deab55096cee582761e22a9bc034e3ece925225b07bf46
- test passed
expect: 89b69d0516f829893c696226650a8687
got   : 89b69d0516f829893c696226650a8687
- test passed
ok
sha512 (4 tests):
expect: 867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252
got   : 867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252
- test passed
expect: e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53c
got   : e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53c
- test passed
expect: d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5
got   : d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5
- test passed
expect: 6e23f27638084b0f7ea1734e0d9841f55dd29ea60a834466f3396bac801fac1eeb63802f03a0b4acd7603e3699c8b74437be83ff01ad7f55dac1ef60f4d56480c35ee68fd52c6936
got   : 6e23f27638084b0f7ea1734e0d9841f55dd29ea60a834466f3396bac801fac1eeb63802f03a0b4acd7603e3699c8b74437be83ff01ad7f55dac1ef60f4d56480c35ee68fd52c6936
- test passed
ok

H:\src\fastpbkdf2>nmake -f Makefile.nmake runbench

Microsoft (R) Program Maintenance Utility Version 14.00.23026.0
Copyright (C) Microsoft Corporation.  All rights reserved.

        bench.exe
openssl,sha1,4194304,1,8.06525
fastpbkdf2,sha1,4194304,1,1.85641
openssl,sha256,4194304,1,13.6501
fastpbkdf2,sha256,4194304,1,4.53963
openssl,sha512,4194304,1,16.3021
fastpbkdf2,sha512,4194304,1,5.89684
openssl,sha1,1048576,4,7.73765
fastpbkdf2,sha1,1048576,4,1.96561
openssl,sha256,1048576,4,13.8061
fastpbkdf2,sha256,1048576,4,4.47723
openssl,sha512,1048576,4,16.1305
fastpbkdf2,sha512,1048576,4,6.00604
openssl,sha1,262144,16,7.95605
fastpbkdf2,sha1,262144,16,1.96561
openssl,sha256,262144,16,13.2601
fastpbkdf2,sha256,262144,16,4.68003
openssl,sha512,262144,16,16.5205
fastpbkdf2,sha512,262144,16,5.97484
openssl,sha1,65536,64,8.09645
fastpbkdf2,sha1,65536,64,1.98121
openssl,sha256,65536,64,13.1353
fastpbkdf2,sha256,65536,64,4.61763
openssl,sha512,65536,64,16.3489
fastpbkdf2,sha512,65536,64,5.81884
openssl,sha1,16384,256,7.95605
fastpbkdf2,sha1,16384,256,2.05921
openssl,sha256,16384,256,13.0105
fastpbkdf2,sha256,16384,256,4.71123
openssl,sha512,16384,256,19.3129
fastpbkdf2,sha512,16384,256,6.73924
openssl,sha1,4096,1024,8.56445
fastpbkdf2,sha1,4096,1024,2.15281
openssl,sha256,4096,1024,14.1649
fastpbkdf2,sha256,4096,1024,5.05443
openssl,sha512,4096,1024,17.5189
fastpbkdf2,sha512,4096,1024,6.44284
        benchmulti.exe
openssl,sha1,4194304,1,16,8.64246,8.90051
fastpbkdf2,sha1,4194304,1,16,2.12161,2.19312
openssl,sha1,4194304,1,32,16.9573,17.444
fastpbkdf2,sha1,4194304,1,32,4.22763,4.33125
openssl,sha1,4194304,1,48,25.631,26.4235
fastpbkdf2,sha1,4194304,1,48,6.45844,6.59538
openssl,sha1,4194304,1,64,34.4762,35.602
fastpbkdf2,sha1,4194304,1,64,8.42405,8.6685
```

## OpenSSL

You need to arrange for openssl to appear in `openssl/`, as follows:

* `openssl/include` -- from the openssl distribution (there will be an `openssl` directory in here containing headers).
* `openssl/lib` -- either DLL link library or static library for `libcrypto`, named `libeay32.lib`.
