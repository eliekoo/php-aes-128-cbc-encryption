<?php


use Illuminate\Http\Request;

class MyController
{

	public $current_version = 1;

	public function encodeParamsData(Request $request){

		// Example input: {"Data":{"id": "1111", "name":"John"},"HashKey":"test123456789000","HashIV":"000987654321test"}
		$input = $request->all();
		
		$enc_requestData = $this->EncryptAesCBC(json_encode($input['Data']), $input['HashKey'], $input['HashIV']);

		// example encryptedData: "ZgvJXiuzzjKXiejvUZgHXqtIq7YRbPnO+UDUYvyZ0+w="
		return $enc_requestData;
	}

	public function decodeParamsData(Request $request){

		// Example input: {"EncryptedData":"ZgvJXiuzzjKXiejvUZgHXqtIq7YRbPnO+UDUYvyZ0+w=","HashKey":"test123456789000","HashIV":"000987654321test"}
		$input = $request->all();

		$dec_responseData = $this->DecryptAesCBC($input['EncryptedData'], $input['HashKey'], $input['HashIV']);

		// Example decryptedData: {"id":"1111","name":"John"}
		return $dec_responseData;
	}

	protected function EncryptAesCBC($data, $key, $iv) 
	{
    	// Use HashKey and HashIV for AES encryption.
    	// Data in json format
    	// AES encryption strength setting mode is 128 bit , CipherMode:CBC, PaddingMode:PKCS7
    	// openssl_encrypt() already does PKCS#7 padding
		
		$ciphertext_raw = openssl_encrypt($data, "AES-128-CBC", $key, OPENSSL_RAW_DATA, $iv);
		
		$enc_result = base64_encode($ciphertext_raw);
		
		return $enc_result;
	}

	public static function DecryptAesCBC($data, $key, $iv) 
	{	
		// Use HashKey and HashIV for AES encryption.
    	// Data in json format
		// AES encryption strength setting mode is 128 bit , CipherMode:CBC, PaddingMode:PKCS7
    	// openssl_decrypt() will removes PKCS#7 padding
		
		$data = base64_decode($data);
		
		$dec_result = openssl_decrypt($data, "AES-128-CBC", $key, OPENSSL_RAW_DATA, $iv);
		
		return $dec_result;
	}

	
}
