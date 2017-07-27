<?php

  date_default_timezone_set ('America/Bogota');

    
    
  /**
  * @func ----- pad_pkcs5
  * @desc ----- Toma el tamaño del bloque del cifrador especificado
  * ----------- segun el formato de encriptacion tripledes
  * @author --- @jhons1101 - elbauldelcodigo.com
  **/
    
  function pad_pkcs5($data) {
      $block_size = mcrypt_get_block_size("tripledes", "cbc");//utilizada para tomar el tamaño de un bloque del cifrado
      $padding_char = $block_size - (strlen($data) % $block_size);
      $data .= str_repeat(chr($padding_char),$padding_char);
      return $data;
  }

  /**
  * @func ----- unpad_pkcs5
  * @desc ----- devuelve el valor ASCII de la cadena caracter
  * @author --- @jhons1101 - elbauldelcodigo.com
  **/

  function unpad_pkcs5($data){
    $length = ord(substr($data, strlen($data)-1));
    $data = substr($data,0,strlen($data)-$length);
    return $data;
  }

  /**
  * @func ----- codificar
  * @desc ----- Devuelve la cadena codificada en formato triple_des (3des)
  * @author --- @jhons1101 - elbauldelcodigo.com
  **/

  function codificar($data) {

      $iv  = "2255488121241524";
      $key = "333333333333333333440215121545454545222222222222";

      //Esta función abre el módulo del algoritmo y el modo a ser utilizado
      $td = mcrypt_module_open(MCRYPT_3DES,"", MCRYPT_MODE_CBC, "");
      $key = pack("H48",$key); // Hexadecimal de 48 caracteres
      $iv = pack("H16",$iv);   // Hexadecimal de 16 caracteres
      mcrypt_generic_init($td, $key, $iv);
      $data = pad_pkcs5($data);
      $desResult = mcrypt_generic($td, $data);
      mcrypt_generic_deinit($td);
      mcrypt_module_close($td);

      return base64_encode($desResult);
  }

  /**
  * @func ----- decodificar
  * @desc ----- Devuelve la cadena descodificada en formato triple_des (3des)
  * @author --- @jhons1101 - elbauldelcodigo.com
  **/

  function decodificar($data) {


      $iv  = "2255488121241524";
      $key = "333333333333333333440215121545454545222222222222";

      $td = mcrypt_module_open(MCRYPT_3DES,"", MCRYPT_MODE_CBC, "");
      $key = pack("H48",$key); // Hexadecimal de 48 caracteres
      $iv = pack("H16",$iv);   // Hexadecimal de 16 caracteres
      mcrypt_generic_init($td, $key, $iv);
      $data = base64_decode($data);
      $desResult = mdecrypt_generic($td, $data);
      mcrypt_generic_deinit($td);
      mcrypt_module_close($td);
      $desResult = unpad_pkcs5($desResult);
      return $desResult;
  }

echo "<pre>"; print_r(codificar('junio2017')); echo "</pre>";
echo "<pre>"; print_r(decodificar(codificar('junio2017'))); echo "</pre>"; 
die("pausa");

?>
