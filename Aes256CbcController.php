<?php


use Illuminate\Http\Request;

class Aes256CbcController
{

	public $current_version = 1;

	public function encodeParamsData(Request $request){

		// Example input: {"Data":{"id": "1111", "name":"John"},"HashKey":"test123456789000","HashIV":"000987654321test"}
		$input = $request->all();
		
		$enc_requestData = $this->EncryptAesCBC(json_encode($input['Data']), $input['HashKey'], $input['HashIV']);

		// example encryptedData: "2D517F805B2A2E91D2BCFA39147F31F735528B18E586BBF4F7D4579700E78181"
		return $enc_requestData;
	}

	public function decodeParamsData(Request $request){

		// Example input: {"EncryptedData":"2D517F805B2A2E91D2BCFA39147F31F735528B18E586BBF4F7D4579700E78181","HashKey":"test123456789000","HashIV":"000987654321test"}
		$input = $request->all();

		$dec_responseData = $this->DecryptAesCBC($input['EncryptedData'], $input['HashKey'], $input['HashIV']);

		// Example decryptedData: {"id":"1111","name":"John"}
		return $dec_responseData;
	}

	//AES 256 CBC encrypt with PKCS7Padding
	protected static function EncryptAesCBC($data, $key, $iv) {
		$enc_result = '';

		$padding = 16 - (strlen($data) % 16);
		$data .= str_repeat(chr($padding), $padding);
		$ciphertext_raw = openssl_encrypt($data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);

		$enc_result = strtoupper(bin2hex($ciphertext_raw));

		return $enc_result;
	}

	//AES 256 CBC decrypt with PKCS7Padding
	protected static function DecryptAesCBC($data, $key, $iv) {
		$dec_result = '';

		$encrypted_data = hex2bin($data);

		$decrypt = openssl_decrypt($encrypted_data, 'AES-256-CBC', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);

		$padding = ord($decrypt[strlen($decrypt) - 1]);
		$dec_result = substr($decrypt, 0, -$padding);

		return $dec_result;
	}

	
}
