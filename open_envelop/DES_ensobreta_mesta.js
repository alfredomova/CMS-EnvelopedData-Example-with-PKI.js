// valida si el navegador soporta File API
if (window.File && window.FileReader && window.FileList && window.Blob) {
	console.log('Great success! All the File APIs are supported.');
} else {
	alert('The File APIs are not fully supported in this browser.');
}

var crypto = window.crypto || window.msCrypto;

// valida si el navegador soporta Crypto API
if(crypto.subtle) {
	console.log('Cryptography API Supported');	 
} else {
	alert('Cryptography API not Supported');
}

String.prototype.endsWith = function(suffix) {
	return this.indexOf(suffix, this.length - suffix.length) !== -1;
};

function _arrayBufferToBase64( buffer ) {
	var binary = '';
	var bytes = new Uint8Array( buffer );
	var len = bytes.byteLength;
	for (var i = 0; i < len; i++) {
		binary += String.fromCharCode( bytes[ i ] );
	}
	return window.btoa( binary );
}
 
function stringToArrayBuffer(str)
    {
        /// <summary>Create an ArrayBuffer from string</summary>
        /// <param name="str" type="String">String to create ArrayBuffer from</param>

        var stringLength = str.length;

        var resultBuffer = new ArrayBuffer(stringLength);
        var resultView = new Uint8Array(resultBuffer);

        for(var i = 0; i < stringLength; i++)
            resultView[i] = str.charCodeAt(i);

        return resultBuffer;
    }

function formatPEM(pem_string) {
    /// <summary>Format string in order to have each line with length equal to 63</summary>
    /// <param name="pem_string" type="String">String to format</param>

    var string_length = pem_string.length;
    var result_string = "";

    for(var i = 0, count = 0; i < string_length; i++, count++)
    {
        if(count > 63)
        {
            result_string = result_string + "\r\n";
            count = 0;
        }

        result_string = result_string + pem_string[i];
    }

    return result_string;
}

///////////////////////////////////////////////////////////

var app = angular.module('des_sobre_app', [ ]);

app.controller("des_sobreCtrl", function($scope ) {

	$scope.password = '';
	var keyArrayBuffer = null;
	var certArrayBuffer = null;
	var fileArrayBuffer = null;
	
	$( document ).ready(function() {


		function handleFileSelect(evt) {
		
			var files = evt.target.files; 

			for (var i = 0, f; f = files[i]; i++) {
					// console.log(f);
					
					var reader = new FileReader();
					
					// Closure to capture the file information.
					reader.onload = (function(theFile) {
						return function(e) {
						
							console.info("B64 >> " + _arrayBufferToBase64(e.target.result));
							
							if (theFile.name.endsWith('.key')){

								keyArrayBuffer = e.target.result; 
								$('#key_b64').val(_arrayBufferToBase64(keyArrayBuffer));


							} else if (theFile.name.endsWith('.cer')){

								certArrayBuffer = e.target.result; 
								$('#cert_b64').val(_arrayBufferToBase64(certArrayBuffer));

							} else if (theFile.name.endsWith('.pdf')) {

								fileArrayBuffer = e.target.result; 
								$('#file_b64').val(_arrayBufferToBase64(fileArrayBuffer));

							}
							
						};
					})(f);

    				function errorHandler(evt) {
					    switch(evt.target.error.code) {
					      case evt.target.error.NOT_FOUND_ERR:
					        alert('File Not Found!');
					        break;
					      case evt.target.error.NOT_READABLE_ERR:
					        alert('File is not readable');
					        break;
					      case evt.target.error.ABORT_ERR:
					        break; // noop
					      default:
					        alert('An error occurred reading this file.');
					    };
					}

    				reader.onerror = errorHandler;

					// LOS MODOS DE LECTURA DE HTML5
					reader.readAsArrayBuffer(f);
					// reader.readAsText(f, 'UTF-8');
					
					console.log("* * * * * * * * * * * * * * * *");
					console.log("name:" + escape(f.name));
					console.log("type:" + f.type);
					console.log("size:" + f.size);
					console.log("last modifided:" + f.lastModifiedDate.toLocaleDateString());
					console.log("* * * * * * * * * * * * * * * *");
					
				}
				
		}

		document.getElementById('key').addEventListener('change', handleFileSelect, false);
		document.getElementById('cert').addEventListener('change', handleFileSelect, false);
		// document.getElementById('file').addEventListener('change', handleFileSelect, false);
	
	});
	
	
	
	$scope.abreSobre = function(){

			console.log("BEGIN >>>>>>>>>>>>> #");

			console.log(" password #" + $scope.password);

			console.log(" #region Decode input certificate ");
            var asn1 = org.pkijs.fromBER(certArrayBuffer);
            var cert_simpl = new org.pkijs.simpl.CERT({ schema: asn1.result });

            console.log(cert_simpl);

            console.log(" #endregion ");



			console.log("  #region Decode input private key ");
			var privateKeyBuffer = keyArrayBuffer;

            console.log(privateKeyBuffer);

            console.log("  #endregion ");



            console.log(" #region Decode CMS Enveloped content ");
            var encodedCMSEnveloped = $("#el_pinche_envelop").val();
            var clearEncodedCMSEnveloped = encodedCMSEnveloped.replace(/(-----(BEGIN|END)( NEW)? CMS-----|\n)/g, '');
            var cmsEnvelopedBuffer = stringToArrayBuffer(window.atob(clearEncodedCMSEnveloped));
            var asn1 = org.pkijs.fromBER(cmsEnvelopedBuffer);
            var cms_content_simpl = new org.pkijs.simpl.CMS_CONTENT_INFO({ schema: asn1.result });
            var cms_enveloped_simp = new org.pkijs.simpl.CMS_ENVELOPED_DATA({ schema: cms_content_simpl.content });
            console.log(" #endregion ");


            cms_enveloped_simp.decrypt(0,
                {
                    recipientCertificate: cert_simpl,
                    recipientPrivateKey: privateKeyBuffer
                }).then(
                function(result)
                {
                    document.getElementById("file_b64").innerHTML = arrayBufferToString(result);
                },
                function(error)
                {

                	console.log(error);

                    alert("ERROR DURING DECRYPTION PROCESS: " + error);
                }
            );


			console.log("<<<<<<<<<<<<<<< END");

	}

		
});