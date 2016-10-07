package vigenere;

/**
 * Vigenere ����/����
 */
public class EncryptDecrypt {

	// �ַ���
	private final static String charStr = "abcdefghijklmnopqrstuvwxyz";

	/**
	 * Vigenere ����
	 * 
	 * @param plaintext
	 *            ����
	 * @param key
	 *            ��Կ
	 * @return ����
	 * @throws Exception
	 */
	public String encrypt(String plaintext, String key) {
		String ciphertext = "";
		int[] plaintextArr, ciphertextArr, keyArr;
		// ���������Ƿ�Ϊ��
		if (plaintext == null || plaintext == "") {
			return "";
		}
		plaintext = preDeal(plaintext);

		plaintextArr = new int[plaintext.length()]; // ���ڴ������ĵ�����
		ciphertextArr = new int[plaintext.length()]; // ���ڴ������ĵ�����
		keyArr = new int[key.length()]; // ���ڴ������ĵ�����

		// �����Ĵ���� ����plaintextArr��
		plaintextArr = convertToArr(plaintext);

		// ����Կ����� ����key��
		keyArr = convertToArr(key);

		// ����
		// �������� ����ciphertext��
		for (int i = 0, j = 0; i < plaintext.length(); i++, j++) {
			j = j % key.length();
			ciphertextArr[i] = (plaintextArr[i] + keyArr[j]) % 26;
		}
		ciphertext = convertToString(ciphertextArr);
		return ciphertext;
	}

	/**
	 * Vigenere ����
	 * 
	 * @param ciphertext
	 *            ����
	 * @param key
	 *            ��Կ
	 * @return ����
	 * @throws Exception
	 */
	public String decrypt(String ciphertext, String key) {
		String plaintext = "";
		int[] plaintextArr, ciphertextArr, keyArr;

		// ���������Ƿ�Ϊ��
		if (ciphertext == null || ciphertext == "") {
			return "";
		}
		ciphertext = preDeal(ciphertext);

		plaintextArr = new int[ciphertext.length()]; // ���ڴ������ĵ�����
		ciphertextArr = new int[ciphertext.length()]; // ���ڴ������ĵ�����
		keyArr = new int[key.length()]; // ���ڴ������ĵ�����

		// �����Ĵ���� ����ciphertextArr��
		ciphertextArr = convertToArr(ciphertext);

		// ����Կ����� ����key��
		keyArr = convertToArr(key);

		// ����
		// �������� ����plaintextArr��
		for (int i = 0, j = 0; i < ciphertext.length(); i++, j++) {
			j = j % key.length();
			plaintextArr[i] = (ciphertextArr[i] - keyArr[j] + 26) % 26;
		}
		plaintext = convertToString(plaintextArr);
		return plaintext;
	}

	/**
	 * Ԥ���� ȥ��26λ��ĸ֮������� ����д��ĸת��ΪСд��ĸ
	 * 
	 * @param text
	 *            ����������
	 * @return Ԥ����������
	 */
	public String preDeal(String text) {
		String dealAfter = "";
		dealAfter = text.replaceAll("[^a-zA-Z]", "");
		return dealAfter.toLowerCase();
	}

	/**
	 * ��int����ת��Ϊ�ַ���
	 */
	public String convertToString(int[] numArr) {
		String str = "";
		for (int i = 0; i < numArr.length; i++) {
			str += charStr.charAt(numArr[i]);
		}
		return str;
	}

	/**
	 * ���ַ���ת��Ϊint����
	 */
	public int[] convertToArr(String text) {
		int[] numArr = new int[text.length()];
		for (int i = 0; i < text.length(); i++) {
			numArr[i] = charStr.indexOf(text.charAt(i));
		}
		return numArr;
	}
}
