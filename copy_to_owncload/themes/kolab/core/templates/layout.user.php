<!DOCTYPE html>
<html>
	<head data-requesttoken="<?php p($_['requesttoken']); ?>"> 
		<title><?php echo isset($_['application']) && !empty($_['application'])?$_['application'].' | ':'' ?>ownCloud <?php echo OC_User::getUser()?' ('.OC_User::getUser().') ':'' ?></title>
		<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
		<link rel="shortcut icon" href="<?php echo image_path('', 'favicon.png'); ?>" /><link rel="apple-touch-icon-precomposed" href="<?php echo image_path('', 'favicon-touch.png'); ?>" />
		<?php foreach($_['cssfiles'] as $cssfile): ?>
			<link rel="stylesheet" href="<?php echo $cssfile; ?>" type="text/css" media="screen" />
		<?php endforeach; ?>
		<script type="text/javascript">
			var oc_webroot = '<?php echo OC::$WEBROOT; ?>';
			var oc_appswebroots = <?php echo $_['apps_paths'] ?>;
			var oc_current_user = '<?php echo OC_User::getUser() ?>';
			var oc_requesttoken = '<?php echo $_['requesttoken']; ?>';
			var oc_requestlifespan = '<?php echo $_['requestlifespan']; ?>';
		</script>
		<?php foreach($_['jsfiles'] as $jsfile): ?>
			<script type="text/javascript" src="<?php echo $jsfile; ?>"></script>
		<?php endforeach; ?>
		<?php foreach($_['headers'] as $header): ?>
			<?php
				echo '<'.$header['tag'].' ';
				foreach($header['attributes'] as $name=>$value) {
					echo "$name='$value' ";
				};
				echo '/>';
			?>
		<?php endforeach; ?>
	</head>

	<body id="<?php echo $_['bodyid'];?>">
		<div id="notification-container">
			<div id="notification"></div>
		</div>
		<div id="content">
			<?php echo $_['content']; ?>
		</div>
	</body>
</html>
