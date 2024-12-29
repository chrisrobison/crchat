<?php
$in = $_REQUEST;
if (isset($_FILES['file'])) {
    $file = $_FILES['file'];

    move_uploaded_file($file['tmp_name'], "uploads/".$file['name']);
    
    $out = ["filename"=>$file['name'], "mimetype"=>$file['type'], "size"=>$file['size'], "url"=>'https://'.$_SERVER['HTTP_HOST']."/crchat/uploads/{$file['name']}"];

    header("Content-Type: application/json");
    print json_encode($out);
}
