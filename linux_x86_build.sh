cd /libsodium-1.0.20
./configure --host=i686-linux-gnu CFLAGS="-m32"  LDFLAGS="-m32" --prefix=$(pwd)/x86 --disable-pie
make -j4
make install
rm -r /compile/prebuilt/libsodium
cp -r x86 /compile/prebuilt/libsodium

export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
cd /compile
cmake -S . -B release -DCMAKE_BUILD_TYPE=Release
cd release
cmake  -DCMAKE_C_FLAGS=-m32 -DCMAKE_CXX_FLAGS=-m32 .
cmake --build . --target crypto_jni -j4
cmake --build . --target main -j4
cp /compile/release/libcrypto_jni.so /product
cp /compile/release/main /product
