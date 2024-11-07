mkdir /libsodium && cd /libsodium
wget https://download.libsodium.org/libsodium/releases/libsodium-1.0.20.tar.gz
tar xf libsodium-1.0.20.tar.gz && cd libsodium-1.0.20
./configure --prefix=$(pwd)/x86_64 --disable-pie
make -j4
make install
rm -r /compile/prebuilt/libsodium
cp -r x86_64 /compile/prebuilt/libsodium

export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
cd /compile
cmake -S . -B release -DCMAKE_BUILD_TYPE=Release
cd release
cmake --build . --target crypto_jni -j4
cmake --build . --target main -j4
cp /compile/release/libcrypto_jni.so /product
cp /compile/release/main /product
