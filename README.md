# PyCrypto-Frida-AES-Hook
Hook PyCrypto AES functions and retrieve Specs with Frida

1) Install frida
2) Open cmd prompt and enter `frida -p <pid> -l PyCrypto_hook.js`
you can get current pid instance with `tasklist | findstr "python"` cmd under windows. Script should work under any OS...

Note: This script is useful if the code you're running is encrypted/compiled but you sure uses PyCrypto/PyCryptoDome(x) library.
