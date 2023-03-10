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
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-GLhlTQ8iRABdZLl6O3oVMWSktQOp6b7In1Zl3/Jr59b6EGGoI1aFkw7cmDA6j6gD" crossorigin="anonymous">
  </head>
  <body>
    <div class="container py-3">
      <header>
        <div class="d-flex align-items-center pb-3 mb-4 border-bottom">
          <a href="https://www.cyberark.com" class="d-flex align-items-center">
            <img src="https://www.cyberark.com/wp-content/uploads/2022/12/cyberark-logo-v2.svg" height="48">
          </a>
          <nav class="d-inline-flex ms-md-auto">
            <a class="me-3 py-2 text-dark text-decoration-none" href="https://docs.cyberark.com">Docs</a>
            <a class="me-3 py-2 text-dark text-decoration-none" href="https://cyberark-customers.force.com/mplace/s/">Marketplace</a>
          </nav>
        </div>
        <div class="pricing-header p-3 pb-md-4 text-center">
          <h1 class="display-6 fw-normal">CyberArk Integration Demo</h1>
          <p class="fs-3 text-muted">Random World Cities!</p>
        </div>
      </header>
      <main>
        <h2 class="display-6 text-center pb-md-4">
          <?php
            echo '<b>'.$row['City'].'</b> is a city in <b>'.$row['District'].'</b>, <b>'.$row['Country'].'</b> with a population of <b>'.$row['Population'].'</b>';
          ?>
        </h2>
        <div class="card p-4 col-lg-5 col-md-5 mx-auto text-center">
          <p class="lead">
            <?php
              echo 'Connected to database <b>'.$data.'</b> on <b>'.$host.'</b>:<b>'.$port.'</b>';
            ?>
          </p>
          <p class="lead">
            <?php
              echo 'Using username: <b>'.$user.'</b> and password: <b>'.$pass.'</b>';
            ?>
          </p>
        </div>
      </main>
      <footer class="my-md-5 pt-md-5 border-top">
        <div class="container">
          <p class="float-end">A CyberArk demo by Joe Tan <a href="mailto:joe.tan@cyberark.com">✉</a></p>
          <p class="mb-1">Style by <a href="https://getbootstrap.com/">Bootstrap</a>.</p>
        </div>
      </footer>
    </div>
  </body>
</html>
