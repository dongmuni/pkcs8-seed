package com.rankwave.pkcs8;

public enum MDSpec {
	MD5(512, 128), SHA0(512, 160), SHA1(512, 160), SHA224(512, 224), SHA256(512, 256), SHA384(1024, 384),
	SHA512(1024, 512), SHA512_224(1024, 224), SHA512_256(1024, 256), SHA3_224(1152, 224), SHA3_256(1088, 256),
	SHA3_384(832, 384), SHA3_512(576, 512), SHAKE128(1344, 0), SHAKE256(1088, 0);

	int blockSize;
	int outputSize;

	MDSpec(int blockSize, int outputSize) {
		this.blockSize = blockSize;
		this.outputSize = outputSize;
	}

	public int getBlockSizeInBits() {
		return blockSize;
	}

	public int getBlockSizeInBytes() {
		return blockSize / 8;
	}

	public int getOutputSizeInBits() {
		return outputSize;
	}

	public int getOutputSizeInBytes() {
		return outputSize / 8;
	}
}

