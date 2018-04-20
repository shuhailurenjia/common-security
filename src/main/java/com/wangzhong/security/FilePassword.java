package com.wangzhong.security;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;

class FilePassword implements Password {

	private String filePathName;
	
	protected String fileContent;
	
	public FilePassword(String pathName) throws IOException{
		this.filePathName = pathName;
		fileContent = readFile(pathName);
	}
	
	public FilePassword(InputStream is) throws IOException{
		fileContent = read(is);
	}
	
	public static String read(InputStream is) throws IOException {
		int len;
		char[] b = new char[100];
		StringBuilder c = new StringBuilder();
		Reader in = new InputStreamReader(is, CharUtil.UTF8);
		try {
			while ((len = in.read(b)) != -1) {
				c.append(b, 0, len);
			}
		} finally {
			in.close();
		}
		return c.toString();
	}
	
	public static String readFile(String fileName) throws IOException{
		FileInputStream stream = new FileInputStream(fileName);
		return read(stream);
	}
	
	public String getFilePathName() {
		return filePathName;
	}
	
	@Override
	public String getPassword() {
		return fileContent;
	}

	@Override
	public boolean checkValidate() {
		return true;
	}

}
