package vigenere;

/**
 * Vigenere 加密/解密
 */
public class EncryptDecrypt {

	// 字符表
	private final static String charStr = "abcdefghijklmnopqrstuvwxyz";

	/**
	 * Vigenere 加密
	 * 
	 * @param plaintext
	 *            明文
	 * @param key
	 *            秘钥
	 * @return 密文
	 * @throws Exception
	 */
	public String encrypt(String plaintext, String key) {
		String ciphertext = "";
		int[] plaintextArr, ciphertextArr, keyArr;
		// 检验明文是否为空
		if (plaintext == null || plaintext == "") {
			return "";
		}
		plaintext = preDeal(plaintext);

		plaintextArr = new int[plaintext.length()]; // 用于储存明文的数组
		ciphertextArr = new int[plaintext.length()]; // 用于储存明文的数组
		keyArr = new int[key.length()]; // 用于储存明文的数组

		// 将明文储存进 数组plaintextArr内
		plaintextArr = convertToArr(plaintext);

		// 将秘钥储存进 数组key内
		keyArr = convertToArr(key);

		// 加密
		// 结果储存进 数组ciphertext内
		for (int i = 0, j = 0; i < plaintext.length(); i++, j++) {
			j = j % key.length();
			ciphertextArr[i] = (plaintextArr[i] + keyArr[j]) % 26;
		}
		ciphertext = convertToString(ciphertextArr);
		return ciphertext;
	}

	/**
	 * Vigenere 解密
	 * 
	 * @param ciphertext
	 *            密文
	 * @param key
	 *            秘钥
	 * @return 明文
	 * @throws Exception
	 */
	public String decrypt(String ciphertext, String key) {
		String plaintext = "";
		int[] plaintextArr, ciphertextArr, keyArr;

		// 检验密文是否为空
		if (ciphertext == null || ciphertext == "") {
			return "";
		}
		ciphertext = preDeal(ciphertext);

		plaintextArr = new int[ciphertext.length()]; // 用于储存明文的数组
		ciphertextArr = new int[ciphertext.length()]; // 用于储存明文的数组
		keyArr = new int[key.length()]; // 用于储存明文的数组

		// 将密文储存进 数组ciphertextArr内
		ciphertextArr = convertToArr(ciphertext);

		// 将秘钥储存进 数组key内
		keyArr = convertToArr(key);

		// 解密
		// 结果储存进 数组plaintextArr内
		for (int i = 0, j = 0; i < ciphertext.length(); i++, j++) {
			j = j % key.length();
			plaintextArr[i] = (ciphertextArr[i] - keyArr[j] + 26) % 26;
		}
		plaintext = convertToString(plaintextArr);
		return plaintext;
	}

	/**
	 * 预处理 去除26位字母之外的内容 将大写字母转换为小写字母
	 * 
	 * @param text
	 *            待处理内容
	 * @return 预处理后的内容
	 */
	public String preDeal(String text) {
		String dealAfter = "";
		dealAfter = text.replaceAll("[^a-zA-Z]", "");
		return dealAfter.toLowerCase();
	}

	/**
	 * 将int数组转换为字符串
	 */
	public String convertToString(int[] numArr) {
		String str = "";
		for (int i = 0; i < numArr.length; i++) {
			str += charStr.charAt(numArr[i]);
		}
		return str;
	}

	/**
	 * 将字符串转换为int数组
	 */
	public int[] convertToArr(String text) {
		int[] numArr = new int[text.length()];
		for (int i = 0; i < text.length(); i++) {
			numArr[i] = charStr.indexOf(text.charAt(i));
		}
		return numArr;
	}
}
