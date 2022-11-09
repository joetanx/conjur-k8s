<!DOCTYPE html>
<?php
  $db_addr=getenv('DBADDR');
  $db_user=getenv('DBUSER');
  $db_pass=getenv('DBPASS');
  $ccp_fqdn=getenv('CCPFQDN');
  $appid=getenv('APPID');
  $query=getenv('QUERY');
  if(!empty($db_addr))
  {
    $host=$db_addr;
    $user=$db_user;
    $pass=$db_pass;
  }
  elseif(file_exists('/conjur/worlddb.json'))
  {
    $json_data = file_get_contents('/conjur/worlddb.json');
    $response_data = json_decode($json_data);
    $host = $response_data->dbaddr;
    $user = $response_data->dbuser;
    $pass = $response_data->dbpass;
  }
  elseif(!empty($ccp_fqdn))
  {
    $ccp_url='https://'.$ccp_fqdn.'/AIMWebService/api/Accounts?AppID='.$appid.'&'.$query;
    $opts = array(
      'ssl'=>array(
        'verify_peer'=>false,
        'verify_peer_name'=>false
      )
    );
    $context = stream_context_create($opts);
    $json_data = file_get_contents($ccp_url, false, $context);
    $response_data = json_decode($json_data);
    $host = $response_data->Address;
    $user = $response_data->UserName;
    $pass = $response_data->Content;
  }
  else
  {
    exit('<h1>No database credentials configured!</h1>');
  }
  $port = '3306';
  $data = 'world';
  $chrs = 'utf8mb4';
  $attr = "mysql:host=$host;port=$port;dbname=$data;charset=$chrs";
  $opts =
  [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES => false,
  ];
  try
  {
    $pdo = new PDO($attr, $user, $pass, $opts);
  }
  catch (PDOException $e)
  {
    exit('<h1>'.$e->getMessage().'</h1>');
  }
  $query = "SELECT city.Name as City,country.name as Country,city.District,city.Population FROM city,country WHERE city.CountryCode = country.Code ORDER BY RAND() LIMIT 0,1";
  $result = $pdo->query($query);
  $row = $result->fetch();
?>
<html>
  <head>
    <link rel="icon" href="https://www.cyberark.com/wp-content/themes/understrap-child/favicon.ico">
    <title>CyberArk Demo</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-Zenh87qX5JnK2Jl0vWa8Ck2rdkQ2Bzep5IDxbcnCeuOxjzrPF/et3URy9Bv1WTRi" crossorigin="anonymous">
  </head>
  <body>
    <header>
      <div class="navbar navbar-dark bg-dark shadow-sm">
        <div class="container">
          <img src="https://docs.cyberark.com/Product-Doc/OnlineHelp/Portal/Content/Resources/_TopNav/Images/Skin/lg-cyberark.svg">
        </div>
      </div>
    </header>
    <main>
      <section class="py-5 text-center container">
        <div class="row py-lg-5">
          <div class="col-lg-12 col-md-12 mx-auto">
            <h1 class="fw-light">CyberArk Integration Demo</h1>
            <h2 class="fw-light">&nbsp</h2>
            <h2 class="fw-light">Random World Cities!</h2>
            <h3 class="fw-light">
              <?php
                echo '<b>'.$row['City'].'</b> is a city in <b>'.$row['District'].'</b>, <b>'.$row['Country'].'</b> with a population of <b>'.$row['Population'].'</b>';
              ?>
            </h3>
            <p class="lead">
              <?php
                echo 'Connected to database <b>'.$data .'</b> on <b>'.$host.'</b>:<b>'.$port.'</b> using username: <b>'.$user.'</b> and password: <b>'.$pass.'</b>';
              ?>
            </p>
            <h2 class="fw-light">&nbsp</h2>
            <p>
              <a href="https://docs.cyberark.com" class="btn btn-primary my-2">CyberArk Docs</a>
              <a href="https://cyberark-customers.force.com/mplace/s/" class="btn btn-secondary my-2">CyberArk Marketplace</a>
            </p>
          </div>
        </div>
      </section>
    </main>
    <footer class="text-muted py-5">
      <div class="container">
        <p class="float-end mb-1">
          <a href="#">Back to top</a>
        </p>
        <p class="mb-1">A CyberArk demo by Joe Tan <a href="mailto:joe.tan@cyberark.com">✉</a></p>
        <p class="mb-0">Style by <a href="https://getbootstrap.com/">Bootstrap</a>.</p>
      </div>
    </footer>
  </body>
</html>