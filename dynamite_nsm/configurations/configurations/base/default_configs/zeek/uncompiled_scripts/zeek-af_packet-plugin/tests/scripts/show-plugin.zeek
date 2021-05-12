# @TEST-EXEC: zeek -NN Zeek::AF_Packet |sed -e 's/version.*)/version)/g' > output
# @TEST-EXEC: btest-diff output
