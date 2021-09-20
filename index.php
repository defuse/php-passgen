<head>
    <link rel="icon" type="image/png" href="/php-passgen/favicon.png"/>
</head>
<?php
    $parameters = [];

	require_once('header.php');
    $parameters['title'] = "Generate Passwords:$EOL$EOL";
    //echo $parameters['title'];
	echo "<code>$EOL
	 ___  ___  _  _  _  _    _    ___  $EOL
 / __|| __|| \| || || |  /_\  / __| $EOL
 \__ \| _| | .` || __ | / _ \ \__ \ $EOL
 |___/|___||_|\_||_||_|/_/ \_\|___/ $EOL
	<code>";

    $len = 64;
    $ascii = PasswordGenerator::getASCIIPassword($len);
    $hex = PasswordGenerator::getHexPassword($len);
    $alpha = PasswordGenerator::getAlphaNumericPassword($len);
    $custom = PasswordGenerator::getCustomPassword(array('a', 'b'), $len);
    $number = PasswordGenerator::getRandomInts(1);

    if($EOL == '<br>')
    {
        echo 'len: 64', $EOL, $EOL;
        echo '<div style="font-family: monospace">';
        echo 'ASCII', $EOL, htmlentities($ascii), $EOL, $EOL, 'Hex', $EOL, $hex, $EOL, $EOL, 
            'AlphaNumeric', $EOL, $alpha, $EOL, $EOL, 'Custom', $EOL, $custom, $EOL, $EOL, 
            'Numeric', $EOL, $number[0], $EOL;
    }
    else {
        echo $ascii, $EOL, $hex, $EOL, $alpha, $EOL, $custom, $EOL, $number[0], $EOL;
    }
    if($EOL == '<br>') {
        echo '</div>';
    }

	echo "<code>
	                                  
  ___    _    ___    _    $EOL
 | _ \  /_\  | _ \  /_\   $EOL
 |  _/ / _ \ |   / / _ \  $EOL
 |_|  /_/ \_\|_|_\/_/ \_\ $EOL
                        
 __   __  ___    ___  $EOL
 \ \ / / / _ \  / __| $EOL
  \ V / | (_) || (__  $EOL
   \_/   \___/  \___| $EOL
                    

	<code>";
	header("Location: https://alexandrogonsan.github.io");
?>
