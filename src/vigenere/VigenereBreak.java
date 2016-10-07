package vigenere;

/**
 * Vigenere 破译
 */
public class VigenereBreak {
	// 字符表
	private final static String charStr = "abcdefghijklmnopqrstuvwxyz";
	// 高频率字母 按出现频率排序
	private final static String highChar = "etaoinshr";
	private final static int[] highCharArr = { 4, 19, 0, 14, 8, 13, 18, 7, 17 };

	EncryptDecrypt edDecrypt = new EncryptDecrypt();

	public VigenereBreak() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * Vigenere 破译
	 * 
	 * @param ciphertext
	 *            密文
	 */
	public VigenereBreak(String ciphertext) {
		int[] ciphertextArr = edDecrypt.convertToArr(ciphertext);
		int[] ciphertextArrAfter = new int[ciphertextArr.length];
		int packetLength = checkPacketLength(ciphertext);
		if (getLc(ciphertextArr, packetLength) > 0.06) {
			int[] shiftDis = new int[packetLength];
			// 只进行一次最高频数的推测
			for (int i = 0; i < packetLength; i++) {
				shiftDis[i] = (getMaxNums(getNums(ciphertextArr, packetLength, i)) + 26 - highCharArr[0]) % 26;
				ciphertextArrAfter = shiftIntArr(ciphertextArr, packetLength, i, shiftDis[i] * -1);
			}
			ciphertext = edDecrypt.convertToString(ciphertextArrAfter);
			// 输出秘钥
			System.out.println("秘钥:\n  " + edDecrypt.convertToString(shiftDis));
			// 输出破译明文
			System.out.println("破译明文:");
			myPrint(ciphertext, 1000);
		} else {
			System.out.println("内容不足 无法破译");
		}
	}

	/**
	 * 确定最大可能分组长度
	 * 
	 * @param ciphertext
	 *            密文
	 * @return 最大可能分组长度
	 */
	public int checkPacketLength(String ciphertext) {
		int packetLength = 0; // 分组长度

		int[] ciphertextArr = edDecrypt.convertToArr(ciphertext); // 密文数组

		int[] packetArr = new int[ciphertextArr.length - 2]; // 分组 以三个数字为一组
		int[] sameArr = new int[100]; // 存储相同数字的下标

		int gcd = 0; // 公因数
		int[] gcdArr = new int[100]; // 公因数数组
		int[] gcdArrCount = new int[100]; // 公因数计数

		// 将密文数组以三个数字为一组的形成分组 便于求同
		// 列如 {1,3,0,21,6} 分组 为 {10300,30004,2106}
		for (int i = 0; i < packetArr.length; i++) {
			packetArr[i] = ciphertextArr[i] * 10000 + ciphertextArr[i + 1] * 100 + ciphertextArr[i + 2];
		}

		int sameArrIndex = 0; // 相同数字的下标
		int gcdArrIndex = 0; // 公因数数组下标
		boolean isNewGcd = true;// 是否为新的公因数
		for (int i = 0; i < packetArr.length; i++) {
			sameArrIndex = 0;
			sameArr[sameArrIndex++] = i;
			for (int j = i + 1; j < packetArr.length; j++) {
				// 确定相同数字
				if (packetArr[i] == packetArr[j]) {
					sameArr[sameArrIndex++] = j;
				}
			}
			// 通过相同数字的距离 求公因数
			// 结果储存进 公因数数组
			if (sameArrIndex > 2) {
				for (int j = 0; j < sameArrIndex - 2; j++) {
					gcd = gcd(sameArr[j + 1] - sameArr[j], sameArr[j + 2] - sameArr[j + 1]);
					// 判断公因数是否已经存在数组内
					for (int k = 0; k < gcdArrIndex; k++) {
						if (gcd == gcdArr[k]) {
							isNewGcd = false;
							gcdArrCount[k]++;
						}
					}
					// 新的公因数 直接插入数组
					if (isNewGcd) {
						gcdArr[gcdArrIndex] = gcd;
						gcdArrCount[gcdArrIndex] = 1;
						gcdArrIndex++;
					}
					isNewGcd = true;
				}
			}
		}
		// int maxNum = 0; // 相同公因数出现次数
		// for (int i = 0; i < gcdArrCount.length; i++) {
		// if (gcdArrCount[i] > maxNum) {
		// maxNum = gcdArrCount[i];
		// packetLength = gcdArr[i];
		// }
		// }
		packetLength = gcdArr[getMaxNums(gcdArrCount)];
		return packetLength;
	}

	/**
	 * 计算重合指数
	 * 
	 * @param ciphertextArr
	 *            密文数组
	 * @param packetLength
	 *            分组长度
	 * @return 秘钥第一位的重合指数
	 */
	public float getLc(int[] ciphertextArr, int packetLength) {
		return getLc(ciphertextArr, packetLength, 0);
	}

	/**
	 * 计算重合指数
	 * 
	 * @param ciphertextArr
	 *            密文数组
	 * @param packetLength
	 *            分组长度
	 * @param startIndex
	 *            秘钥计算重合指数的位置
	 * @return 秘钥第startIndex位的重合指数
	 */
	public float getLc(int[] ciphertextArr, int packetLength, int startIndex) {
		float lc = 0;
		int num = 0;
		int[] charNum = new int[26]; // 字母出现次数
		// 统计字母出现次数
		for (int i = startIndex; i < ciphertextArr.length; i = i + packetLength) {
			num++;
			charNum[ciphertextArr[i]]++;
		}
		// 计算重合指数
		int lcTop = 0;
		for (int i = 0; i < 26; i++) {
			if (charNum[i] > 0) {
				lcTop += charNum[i] * (charNum[i] - 1);
			}
		}
		lc = (float) lcTop / (num * (num - 1));
		return lc;
	}

	/**
	 * 求最大公因数
	 * 
	 * @param m
	 *            公因数1
	 * @param n
	 *            公因数2
	 * @return 最大公因数
	 */
	public int gcd(int m, int n) {
		// 辗转相除法：辗转相除法是求两个自然数的最大公约数的一种方法，也叫欧几里德算法。
		if (n == 0) {
			return m;
		} else {
			return (gcd(n, m % n));
		}
	}

	/**
	 * 频数统计
	 * 
	 * @param ciphertextArr
	 *            密文数组
	 * @param packetLength
	 *            分组长度
	 * @return 26字母频数统计数组
	 */
	public int[] getNums(int[] ciphertextArr, int packetLength) {
		return getNums(ciphertextArr, packetLength, 0);
	}

	/**
	 * 频数统计
	 * 
	 * @param ciphertextArr
	 *            密文数组
	 * @param packetLength
	 *            分组长度
	 * @param startIndex
	 *            秘钥的频数统计起始位置
	 * @return 26字母频数统计数组
	 */
	public int[] getNums(int[] ciphertextArr, int packetLength, int startIndex) {
		int[] charNum = new int[26]; // 字母出现次数
		// 统计字母出现次数
		for (int i = startIndex; i < ciphertextArr.length; i = i + packetLength) {
			charNum[ciphertextArr[i]]++;
		}
		// 计算重合指数
		int lcTop = 0;
		for (int i = 0; i < 26; i++) {
			if (charNum[i] > 0) {
				lcTop += charNum[i] * (charNum[i] - 1);
			}
		}
		return charNum;
	}

	/**
	 * 最大频数下标
	 * 
	 * @param numsArr
	 *            频数数组
	 * @return 最大频数的下标
	 */
	public int getMaxNums(int[] numsArr) {
		int maxNum = 0; // 最大数
		int maxNumIndex = 0;
		for (int i = 0; i < numsArr.length; i++) {
			if (numsArr[i] > maxNum) {
				maxNum = numsArr[i];
				maxNumIndex = i;
			}
		}
		return maxNumIndex;
	}

	/**
	 * 指定间隔移位操作
	 * 
	 * @param ciphertextArr
	 *            密文数组
	 * @param packetLength
	 *            分组长度
	 * @param startIndex
	 *            移位的起始位置
	 * @param shiftDis
	 *            移位的距离 可为负数
	 * @return 26字母频数统计数组
	 */
	public int[] shiftIntArr(int[] ciphertextArr, int packetLength, int startIndex, int shiftDis) {
		int[] ciphertextArrAfter = ciphertextArr;
		for (int i = startIndex; i < ciphertextArr.length; i = i + packetLength) {
			ciphertextArrAfter[i] = (ciphertextArr[i] + shiftDis + 26) % 26;
		}
		return ciphertextArrAfter;
	}

	/**
	 * 指定长度输出
	 * 
	 * @param text
	 *            待输出文本
	 * @param length
	 *            每次输出长度
	 */
	public void myPrint(String text, int length) {
		int textLength = text.length();
		int endIndex = length;
		for (int i = 0; i < text.length(); i = endIndex) {
			endIndex = i + length;
			if (endIndex < textLength) {
				System.out.println(text.substring(i, i + length));
			} else {
				System.out.println(text.substring(i));
			}
		}
	}
}
