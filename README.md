# secure_network_messaging_crypto_lib

crypto library for java project SecureNetowrkMessaging

## Build instructions

1. follow the installation guide on the official libsodium [website](https://doc.libsodium.org/installation), you may need the `-fPIC` flag when compiling. [if you are running ubuntu 24.04 on x86_64 platform, you *may* skip this step *for testing purpose*. (you can found the prebuilt static library at prebuilt/x86_64 dir) But as a rule of thumb, always build cryptographic library *on your own*]

2. copy the static library you built in step 1 to the `prebuilt` directory, modify the `CMakeLists.txt` as needed

3. built the `crypto_lib` target, this is the jni library you need

4. [*optional but highly recommended*]
   
   build the `main` target and generate your own key exchange key pair, replace the pubic one in `src/main/java/us/leaf3stones/snm/crypto/LengthMessageCrypto.java` in the java project
