# secure_network_messaging_crypto_lib

crypto library for java project SecureNetowrkMessaging

## Build with Docker

> [!NOTE]
> 
> Rebuild the docker image each time you change the source code.

1. clone the repo
   
   ```bash
   git clone https://github.com/lry127/secure_network_messaging_crypto_lib.git
   ```

2. build docker image
   
   ```bash
   docker build . -t secure_network_messaging_crypto_lib --network host
   ```

3. build the library
   
   - linux x86 target
     
     ```bash
     docker run -v ./product:/product  secure_network_messaging_crypto_lib linux_x86_build.sh
     ```
   
   - linux x86_64 target
     
     ```bash
     docker run -v ./product:/product  secure_network_messaging_crypto_lib linux_x86_64_build.sh
     ```

4. library will be placed at `./product` directory

## Build instructions (Manually)

1. follow the installation guide on the official libsodium [website](https://doc.libsodium.org/installation), you may need the `-fPIC` and `--disable-pie` flag when compiling.

    If you are running ubuntu 24.04 on x86_64 platform, you *may* skip this step. (you can found the prebuilt static library under `prebuilt/libsodium` dir) But as a rule of thumb, always build cryptographic library *on your own*

2. copy the static library you built in step 1 to the `prebuilt` directory

3. build the `crypto_jni` target, this is the jni library you need

4. [*optional but highly recommended*]
   
   build the `main` target and generate your own key exchange key pair, replace the pubic one in `src/main/java/us/leaf3stones/snm/crypto/LengthMessageCrypto.java` in the java project
