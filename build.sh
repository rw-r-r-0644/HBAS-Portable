mkdir build
cd sd_loader
make clean
make
cd ..
cd installer
make clean
make
cd bin
cp -R *.bin ../../build
cd ..
cd ..

