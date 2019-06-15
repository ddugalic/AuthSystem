<?php
	//definiranje konstanti
	define("PBKDF2_HASH_ALGORITHM", "sha256");		//algoritam za kriptiranje je sha256
	define("PBKDF2_ITERATIONS", 1000);		//broj iteracija pri kriptiranju
	define("PBKDF2_SALT_BYTE_SIZE", 24);		//veličina salt u bajtovima
	define("PBKDF2_HASH_BYTE_SIZE", 24);		//veličina kriptirane lozinke u bajtovima
	
	//konstante potrebne za usporedbu lozinke i lozinke iz baze, da se za obje lozike koristi isto kriptiranje
	define("HASH_SECTIONS", 4);		//nakon što se napravi explode() lozinke iz baze indeksi pojedinih djelova
	define("HASH_ALGORITHM_INDEX", 0);		//indeks na kojemu se nalazi algoritam sha256
	define("HASH_ITERATION_INDEX", 1);		//indeks za broj iteracija 1000
	define("HASH_SALT_INDEX", 2);		//indeks za salt
	define("HASH_PBKDF2_INDEX", 3);		//indeks gdje je lozinka
	
	class AuthSystem{
		private $databaseConnection;		//varijabla u koju spremamo spoj na bazu podataka
		function __construct($dsn, $user = null, $pass = null, $options = null){		//konstruktor sa 4 parametra
			try{		//da se korisniku ne zaustavi program pri pogrešci, mi želimo upravljati iznimkama i ispisati vlastitu poruku
				$this->databaseConnection = new PDO ($dsn, $user, $pass, $options);
				print "Connection successfull<br>";
			}
			catch(PDOException $e){
				print 'Connection failed: ' . $e->getMessage() ."<br>";
			}
			if(!$this->DataTablesExists()){
				$this->CreateTables();
			}
		}
		private function DataTablesExists(){
			try{		//ako se dogodi pogreška preskače se na catch blok
				if(!$this->databaseConnection->query("select 1 from users"))		//$this->databaseConnection->query u ovu varijablu je spremljen spoj na bazu
					return false;
				else		//upit nad tablicom users, ako ne postoji korisnik vraća false, ako postoji true
					return true;
			}
			catch (PDOException $e){
				return false;
			}
		}
		private function CreateTables(){		//stvara tablicu users ako ona ne postoji
			$query = "";
			$query .= "CREATE TABLE users";		//SQL upit za stvaranje tablice
			$query .= "(";
			$query .= "id INT NOT NULL AUTO_INCREMENT,";
			$query .= "username VARCHAR(50) NOT NULL UNIQUE,";
			$query .= "hash VARCHAR(255) NOT NULL,";
			$query .= "PRIMARY KEY (id)";
			$query .= ");";
			
			$this->databaseConnection->exec($query);		//pokretanje gornjeg upita
			if(!$this->DataTablesExists()){		//provjerava jesmo li uspješno stvorili tablicu pozivom funkcije DataTablesExists()
				var_dump($this->databaseConnection->errorInfo());
				throw new Exception("Error while creating database!");
			}
		}
		public function CreateUser($username, $password){		// funkcija koja kreira korisnika pri registraciji
			$hash = $this->create_hash($password);		//poziv funkcije za kriptiranje lozinke
			
			$query = "";
			$query .= "INSERT INTO users";
			$query .= "(username, hash)";
			$query .= "VALUES";
			$query .= "(:username, :hash);";
			
			$stmt = $this->databaseConnection->prepare($query);
			
			$stmt->bindParam(':username', $username, PDO::PARAM_STR, 50);
			$stmt->bindParam(':hash', $hash, PDO::PARAM_STR, 255);
			
			if(!$stmt->execute()){
				throw new Exception("Error while creating user!");
			}
		}
		//funkcija koja vrši prijavu korisnika, parametri su korisničko ime i lozinka
		//ako su jednaki onima u bazi prijaviti će korisnika
		public function AuthenticateUser($username, $password){
			$query = "";
			//upit nad bazom gdje dohvaćamo hash i id za korisničko ime uneseno u obrazac
			$query .= "SELECT hash, id FROM users";
			$query .= " WHERE username LIKE :username;";
			//prepared upit za PDO
			$stmt = $this->databaseConnection->prepare($query);
			$stmt->bindParam(':username', $username, PDO::PARAM_STR, 50);		//povezujemo pripremljeni upit sa varijablama
			
			if($stmt->execute()){
				$data = $stmt->fetchAll();
				if(count($data) === 0){		//ako nema korisničkog imena u bazi postavi SESSION na false
					$_SESSION["authenticated"] = false;		//korisnik nije prijavljen
					return;
				}
				//u varijable spremamo hash i id iz baze
				$hash = $data[0]['hash'];
				$id = $data[0]['id'];
				//validiramo unesenu lozinku i hash iz baze
				if($this->validate_password($password, $hash)){
					$_SESSION["authenticated"] = true;
					$_SESSION["username"] = $username;
					$_SESSION["userId"] = $id;
				}
				else{
					$_SESSION["authenticated"] = false;
				}
			}
			else{
				throw new Exception("Failed to prepare statement!");
			}
		}
		//funkcija provjerava je li korisnik prijavljen
		//ovo će se koristiti za provjeru prijave i pristup sadržajima za prijavljene korisnike
		public function UserIsAuthentic(){
			//provjerava je li postavljen session za prijavu, ako nije vraća false
			if(isset($_SESSION["authenticated"]))
				return $_SESSION["authenticated"];
			else
				return false;
		}
		//funkcija za priomjenu lozinke
		public function ChangeUserPassword($id, $newPassword){
			//pravimo hash lozinke pomoću gotove funkcije create_hash
			$hash = $this->create_hash($newPassword);
			$query = "";
			//upit za promjenu lozinke
			$query .= " UPDATE users";
			$query .= " SET hash = :hash";
			$query .= " WHERE id = :id;";
			//prepared upit za PDO
			$stmt = $this->databaseConnection->prepare($query);
			
			$stmt->bindParam(':hash', $hash, PDO::PARAM_STR, 255);
			$stmt->bindParam(':id', $id, PDO::PARAM_INT);
			//pokretanje upita
			if(!$stmt->execute()){
				throw new Exception("Error while updating user password!");
			}
		}
		//password hashing methods
		private function create_hash($password){
			//Generira random niz od 24 znaka jer je PBKDF2_SALT_BYTE_SIZE=24
			$salt = base64_encode(mcrypt_create_iv(PBKDF2_SALT_BYTE_SIZE, MCRYPT_DEV_URANDOM));
			//funkcija sa return vraća kriptiranu lozinku, vraća hash algoritam:broj iteracija:salt:lozinku
			return PBKDF2_HASH_ALGORITHM . ":" . PBKDF2_ITERATIONS . ":" . $salt . ":" .
				base64_encode($this->pbkdf2(		//poziv funkcije pbkdf2 koja radi kriptiranje
					PBKDF2_HASH_ALGORITHM,		//ovdje koristimo konstante koje smo definirali na početku
					$password,
					$salt,
					PBKDF2_ITERATIONS,
					PBKDF2_HASH_BYTE_SIZE,
					true
				));
		}
		//funkcija za validaciju lozinke, je li utipkana lozinka iz obrasca jednaka lozinci iz baze
		public function validate_password($password, $correct_hash){
			//razdvaja loziku iz baze na dijelove(algoritam, hash, salt, broj iteracija i lozinka)
			$params = explode(":", $correct_hash);
			if(count($params) < HASH_SECTIONS)
				return false;
			//računamo hash za utipkanu lozinku i sa slow_equals funkcijom uspoređujemo sa postojećim hashom u bazi
			//novi hash se računa sa istim parametrima kao i lozinka iz baze (koristimo $params)
			$pbkdf2 = base64_decode($params[HASH_PBKDF2_INDEX]);
			return $this->slow_equals(
				$pbkdf2,
				$this->pbkdf2(
					$params[HASH_ALGORITHM_INDEX],
					$password,
					$params[HASH_SALT_INDEX],
					(int)$params[HASH_ITERATION_INDEX],
					strlen($pbkdf2),
					true
				)
			);
		}
		//provjerava jesu li $a i $b jednaki
		private function slow_equals($a, $b){
			//jesu li iste dužine, ako jesu diff će biti jednak 0
			//^ je xor operator nad bitovima
			$diff = strlen($a) ^ strlen($b);
			//ako su iste dužine provjeravamo znak po znak od $a i $b gdje su $a i $b stringovi
			//prvi znak, pa drugi i tako sve do zadnjeg znaka
			for($i = 0; $i < strlen($a) && $i < strlen($b); $i++){
				//ako su isti $diff će biti 0, inače 1
				//funkcija ord vraća brojčanu vrijednost znaka od 0 do 255
				//operator |= uspoređuje sa prethodnom vrijednosti $diff i rezultatom usporedbe $a i $b
				$diff |= ord($a[$i]) ^ ord($b[$i]);
			}
			//ako je $diff ostao 0, stringovi su jednaki
			return $diff === 0;
		}
		//funkcija koja računa kriptiranu lozinku pomoću sha256
		private function pbkdf2($algorithm, $password, $salt, $count, $key_length, $raw_output = false){
			$algorithm = strtolower($algorithm);
			//provjerava postoji li zadani algoritam u popisu algoritama
			//hash_algos() vraća popis algoritama
			if(!in_array($algorithm, hash_algos(), true))
				trigger_error('PBKDF2 ERROR: Invalid parameters.', E_USER_ERROR);
			//provjerava ispravnost duljine ključa i broja iteracija
			if($count <= 0 || $key_length <= 0)
				trigger_error('PBKDF2 ERROR: Invalid parameters.', E_USER_ERROR);
			//ako postoji hash_pbkdf2 funkcija kriptiraj loziku
			if(function_exists("hash_pbkdf2")){
				if(!$raw_output){
					$key_length = $key_length * 2;
				}
				//ako se izvede ovaj dio return prekida izvođenje ostatka funkcije
				return hash_pbkdf2($algorithm, $password, $salt, $count, $key_length, $raw_output);
			}
			$hash_length = strlen(hash($algorithm, "", true));
			$block_count = ceil($key_length / $hash_length);
			//ako ne postoji hash_pbkdf2 funkcija sami kriptiramo lozinku
			$output = "";
			for($i = 1; $i <= $block_count; $i++){
				$last = $salt . pack("N", $i);
				$last = $xorsum = hash_hmac($algorithm, $last, $password, true);
				for($j = 1; $j < $count; $j++){
					$xorsum ^= ($last = hash_hmac($algorithm, $last, $password, true));
				}
				$output .= $xorsum;
			}
			if($raw_output)
				return substr($output, 0, $key_length);
			else
				return bin2hex(substr($output, 0, $key_length));
		}
	}
?>