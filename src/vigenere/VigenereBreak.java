package vigenere;

/**
 * Vigenere ����
 */
public class VigenereBreak {
	// �ַ���
	private final static String charStr = "abcdefghijklmnopqrstuvwxyz";
	// ��Ƶ����ĸ ������Ƶ������
	private final static String highChar = "etaoinshr";
	private final static int[] highCharArr = { 4, 19, 0, 14, 8, 13, 18, 7, 17 };

	EncryptDecrypt edDecrypt = new EncryptDecrypt();

	public VigenereBreak() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * Vigenere ����
	 * 
	 * @param ciphertext
	 *            ����
	 */
	public VigenereBreak(String ciphertext) {
		int[] ciphertextArr = edDecrypt.convertToArr(ciphertext);
		int[] ciphertextArrAfter = new int[ciphertextArr.length];
		int packetLength = checkPacketLength(ciphertext);
		if (getLc(ciphertextArr, packetLength) > 0.06) {
			int[] shiftDis = new int[packetLength];
			// ֻ����һ�����Ƶ�����Ʋ�
			for (int i = 0; i < packetLength; i++) {
				shiftDis[i] = (getMaxNums(getNums(ciphertextArr, packetLength, i)) + 26 - highCharArr[0]) % 26;
				ciphertextArrAfter = shiftIntArr(ciphertextArr, packetLength, i, shiftDis[i] * -1);
			}
			ciphertext = edDecrypt.convertToString(ciphertextArrAfter);
			// �����Կ
			System.out.println("��Կ:\n  " + edDecrypt.convertToString(shiftDis));
			// �����������
			System.out.println("��������:");
			myPrint(ciphertext, 1000);
		} else {
			System.out.println("���ݲ��� �޷�����");
		}
	}

	/**
	 * ȷ�������ܷ��鳤��
	 * 
	 * @param ciphertext
	 *            ����
	 * @return �����ܷ��鳤��
	 */
	public int checkPacketLength(String ciphertext) {
		int packetLength = 0; // ���鳤��

		int[] ciphertextArr = edDecrypt.convertToArr(ciphertext); // ��������

		int[] packetArr = new int[ciphertextArr.length - 2]; // ���� ����������Ϊһ��
		int[] sameArr = new int[100]; // �洢��ͬ���ֵ��±�

		int gcd = 0; // ������
		int[] gcdArr = new int[100]; // ����������
		int[] gcdArrCount = new int[100]; // ����������

		// ��������������������Ϊһ����γɷ��� ������ͬ
		// ���� {1,3,0,21,6} ���� Ϊ {10300,30004,2106}
		for (int i = 0; i < packetArr.length; i++) {
			packetArr[i] = ciphertextArr[i] * 10000 + ciphertextArr[i + 1] * 100 + ciphertextArr[i + 2];
		}

		int sameArrIndex = 0; // ��ͬ���ֵ��±�
		int gcdArrIndex = 0; // �����������±�
		boolean isNewGcd = true;// �Ƿ�Ϊ�µĹ�����
		for (int i = 0; i < packetArr.length; i++) {
			sameArrIndex = 0;
			sameArr[sameArrIndex++] = i;
			for (int j = i + 1; j < packetArr.length; j++) {
				// ȷ����ͬ����
				if (packetArr[i] == packetArr[j]) {
					sameArr[sameArrIndex++] = j;
				}
			}
			// ͨ����ͬ���ֵľ��� ������
			// �������� ����������
			if (sameArrIndex > 2) {
				for (int j = 0; j < sameArrIndex - 2; j++) {
					gcd = gcd(sameArr[j + 1] - sameArr[j], sameArr[j + 2] - sameArr[j + 1]);
					// �жϹ������Ƿ��Ѿ�����������
					for (int k = 0; k < gcdArrIndex; k++) {
						if (gcd == gcdArr[k]) {
							isNewGcd = false;
							gcdArrCount[k]++;
						}
					}
					// �µĹ����� ֱ�Ӳ�������
					if (isNewGcd) {
						gcdArr[gcdArrIndex] = gcd;
						gcdArrCount[gcdArrIndex] = 1;
						gcdArrIndex++;
					}
					isNewGcd = true;
				}
			}
		}
		// int maxNum = 0; // ��ͬ���������ִ���
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
	 * �����غ�ָ��
	 * 
	 * @param ciphertextArr
	 *            ��������
	 * @param packetLength
	 *            ���鳤��
	 * @return ��Կ��һλ���غ�ָ��
	 */
	public float getLc(int[] ciphertextArr, int packetLength) {
		return getLc(ciphertextArr, packetLength, 0);
	}

	/**
	 * �����غ�ָ��
	 * 
	 * @param ciphertextArr
	 *            ��������
	 * @param packetLength
	 *            ���鳤��
	 * @param startIndex
	 *            ��Կ�����غ�ָ����λ��
	 * @return ��Կ��startIndexλ���غ�ָ��
	 */
	public float getLc(int[] ciphertextArr, int packetLength, int startIndex) {
		float lc = 0;
		int num = 0;
		int[] charNum = new int[26]; // ��ĸ���ִ���
		// ͳ����ĸ���ִ���
		for (int i = startIndex; i < ciphertextArr.length; i = i + packetLength) {
			num++;
			charNum[ciphertextArr[i]]++;
		}
		// �����غ�ָ��
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
	 * ���������
	 * 
	 * @param m
	 *            ������1
	 * @param n
	 *            ������2
	 * @return �������
	 */
	public int gcd(int m, int n) {
		// շת�������շת���������������Ȼ�������Լ����һ�ַ�����Ҳ��ŷ������㷨��
		if (n == 0) {
			return m;
		} else {
			return (gcd(n, m % n));
		}
	}

	/**
	 * Ƶ��ͳ��
	 * 
	 * @param ciphertextArr
	 *            ��������
	 * @param packetLength
	 *            ���鳤��
	 * @return 26��ĸƵ��ͳ������
	 */
	public int[] getNums(int[] ciphertextArr, int packetLength) {
		return getNums(ciphertextArr, packetLength, 0);
	}

	/**
	 * Ƶ��ͳ��
	 * 
	 * @param ciphertextArr
	 *            ��������
	 * @param packetLength
	 *            ���鳤��
	 * @param startIndex
	 *            ��Կ��Ƶ��ͳ����ʼλ��
	 * @return 26��ĸƵ��ͳ������
	 */
	public int[] getNums(int[] ciphertextArr, int packetLength, int startIndex) {
		int[] charNum = new int[26]; // ��ĸ���ִ���
		// ͳ����ĸ���ִ���
		for (int i = startIndex; i < ciphertextArr.length; i = i + packetLength) {
			charNum[ciphertextArr[i]]++;
		}
		// �����غ�ָ��
		int lcTop = 0;
		for (int i = 0; i < 26; i++) {
			if (charNum[i] > 0) {
				lcTop += charNum[i] * (charNum[i] - 1);
			}
		}
		return charNum;
	}

	/**
	 * ���Ƶ���±�
	 * 
	 * @param numsArr
	 *            Ƶ������
	 * @return ���Ƶ�����±�
	 */
	public int getMaxNums(int[] numsArr) {
		int maxNum = 0; // �����
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
	 * ָ�������λ����
	 * 
	 * @param ciphertextArr
	 *            ��������
	 * @param packetLength
	 *            ���鳤��
	 * @param startIndex
	 *            ��λ����ʼλ��
	 * @param shiftDis
	 *            ��λ�ľ��� ��Ϊ����
	 * @return 26��ĸƵ��ͳ������
	 */
	public int[] shiftIntArr(int[] ciphertextArr, int packetLength, int startIndex, int shiftDis) {
		int[] ciphertextArrAfter = ciphertextArr;
		for (int i = startIndex; i < ciphertextArr.length; i = i + packetLength) {
			ciphertextArrAfter[i] = (ciphertextArr[i] + shiftDis + 26) % 26;
		}
		return ciphertextArrAfter;
	}

	/**
	 * ָ���������
	 * 
	 * @param text
	 *            ������ı�
	 * @param length
	 *            ÿ���������
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
