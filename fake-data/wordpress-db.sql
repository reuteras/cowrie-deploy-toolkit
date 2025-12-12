-- WordPress Fake Database for Honeypot
-- This database contains realistic fake blog data to make the honeypot more convincing
-- Generated: 2024-01-15

-- Users table
CREATE TABLE IF NOT EXISTS `wp_users` (
  `ID` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `user_login` varchar(60) NOT NULL,
  `user_pass` varchar(255) NOT NULL,
  `user_nicename` varchar(50) NOT NULL,
  `user_email` varchar(100) NOT NULL,
  `user_url` varchar(100) NOT NULL,
  `user_registered` datetime NOT NULL,
  `user_activation_key` varchar(255) NOT NULL,
  `user_status` int(11) NOT NULL,
  `display_name` varchar(250) NOT NULL,
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `wp_users` VALUES
(1,'admin','$P$B5t3Q9wXKvJZ4L2mH8nP7kR1sT6uV9w','admin','admin@dmz-web01.local','','2024-01-01 10:00:00','',0,'Administrator'),
(2,'editor','$P$BxYz2A3bC4dE5fG6hI7jK8lM9nO0pQ','editor','editor@dmz-web01.local','','2024-01-05 14:30:00','',0,'Content Editor'),
(3,'dbadmin','$P$B1a2b3c4d5e6f7g8h9i0j1k2l3m4n5','dbadmin','dba@dmz-web01.local','','2024-01-10 09:15:00','',0,'Database Admin');

-- Posts table
CREATE TABLE IF NOT EXISTS `wp_posts` (
  `ID` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `post_author` bigint(20) unsigned NOT NULL,
  `post_date` datetime NOT NULL,
  `post_date_gmt` datetime NOT NULL,
  `post_content` longtext NOT NULL,
  `post_title` text NOT NULL,
  `post_excerpt` text NOT NULL,
  `post_status` varchar(20) NOT NULL,
  `comment_status` varchar(20) NOT NULL,
  `ping_status` varchar(20) NOT NULL,
  `post_password` varchar(255) NOT NULL,
  `post_name` varchar(200) NOT NULL,
  `to_ping` text NOT NULL,
  `pinged` text NOT NULL,
  `post_modified` datetime NOT NULL,
  `post_modified_gmt` datetime NOT NULL,
  `post_content_filtered` longtext NOT NULL,
  `post_parent` bigint(20) unsigned NOT NULL,
  `guid` varchar(255) NOT NULL,
  `menu_order` int(11) NOT NULL,
  `post_type` varchar(20) NOT NULL,
  `post_mime_type` varchar(100) NOT NULL,
  `comment_count` bigint(20) NOT NULL,
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `wp_posts` VALUES
(1,1,'2024-01-15 10:00:00','2024-01-15 10:00:00','Welcome to our corporate blog. This site contains internal updates, project documentation, and technical notes.','Welcome to DMZ-WEB01 Internal Blog','','publish','open','open','','welcome-dmz-web01','','','2024-01-15 10:00:00','2024-01-15 10:00:00','',0,'http://dmz-web01.local/?p=1',0,'post','',3),
(2,2,'2024-01-20 14:30:00','2024-01-20 14:30:00','Q1 2024 infrastructure migration is progressing on schedule. All critical systems have been moved to the new data center. Database backups are stored in /root/backup for emergency recovery.','Q1 Infrastructure Migration Update','','publish','open','open','','q1-infrastructure-migration','','','2024-01-20 14:30:00','2024-01-20 14:30:00','',0,'http://dmz-web01.local/?p=2',0,'post','',2),
(3,1,'2024-01-25 09:15:00','2024-01-25 09:15:00','Reminder: All employees must complete security training by end of Q1. VPN credentials expire on Feb 28. Contact IT for renewal. Financial reports available on internal SharePoint.','Security Training Reminder','','publish','open','open','','security-training-reminder','','','2024-01-25 09:15:00','2024-01-25 09:15:00','',0,'http://dmz-web01.local/?p=3',0,'post','',1),
(4,3,'2024-02-01 11:00:00','2024-02-01 11:00:00','MySQL database maintenance completed successfully. Performance improvements observed across all application databases. Remember: Database credentials are managed centrally - do not hardcode passwords in application configs.','Database Maintenance Complete','','publish','closed','closed','','database-maintenance-complete','','','2024-02-01 11:00:00','2024-02-01 11:00:00','',0,'http://dmz-web01.local/?p=4',0,'post','',0);

-- Comments table
CREATE TABLE IF NOT EXISTS `wp_comments` (
  `comment_ID` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `comment_post_ID` bigint(20) unsigned NOT NULL,
  `comment_author` tinytext NOT NULL,
  `comment_author_email` varchar(100) NOT NULL,
  `comment_author_url` varchar(200) NOT NULL,
  `comment_author_IP` varchar(100) NOT NULL,
  `comment_date` datetime NOT NULL,
  `comment_date_gmt` datetime NOT NULL,
  `comment_content` text NOT NULL,
  `comment_karma` int(11) NOT NULL,
  `comment_approved` varchar(20) NOT NULL,
  `comment_agent` varchar(255) NOT NULL,
  `comment_type` varchar(20) NOT NULL,
  `comment_parent` bigint(20) unsigned NOT NULL,
  `user_id` bigint(20) unsigned NOT NULL,
  PRIMARY KEY (`comment_ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `wp_comments` VALUES
(1,1,'John Smith','jsmith@company.local','','192.168.1.100','2024-01-15 11:30:00','2024-01-15 11:30:00','Great to see the blog is up! Looking forward to project updates.',0,'1','Mozilla/5.0','',0,0),
(2,1,'Sarah Johnson','sjohnson@company.local','','192.168.1.101','2024-01-15 14:00:00','2024-01-15 14:00:00','Will this be used for all internal communications or just IT updates?',0,'1','Mozilla/5.0','',0,0),
(3,1,'IT Admin','admin@dmz-web01.local','','192.168.1.10','2024-01-15 15:00:00','2024-01-15 15:00:00','All departments can post updates here. Contact admin for posting access.',0,'1','Mozilla/5.0','',0,1),
(4,2,'Mike Chen','mchen@company.local','','192.168.1.102','2024-01-20 16:00:00','2024-01-20 16:00:00','Good work on the migration! Any downtime expected for remaining systems?',0,'1','Mozilla/5.0','',0,0),
(5,2,'IT Admin','admin@dmz-web01.local','','192.168.1.10','2024-01-20 17:00:00','2024-01-20 17:00:00','No downtime planned. All migrations during maintenance windows.',0,'1','Mozilla/5.0','',0,1),
(6,3,'Lisa Williams','lwilliams@company.local','','192.168.1.103','2024-01-25 10:00:00','2024-01-25 10:00:00','Completed my security training yesterday. Very informative!',0,'1','Mozilla/5.0','',0,0);

-- User metadata table
CREATE TABLE IF NOT EXISTS `wp_usermeta` (
  `umeta_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `user_id` bigint(20) unsigned NOT NULL,
  `meta_key` varchar(255) DEFAULT NULL,
  `meta_value` longtext,
  PRIMARY KEY (`umeta_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `wp_usermeta` VALUES
(1,1,'wp_capabilities','a:1:{s:13:\"administrator\";b:1;}'),
(2,1,'wp_user_level','10'),
(3,1,'nickname','admin'),
(4,2,'wp_capabilities','a:1:{s:6:\"editor\";b:1;}'),
(5,2,'wp_user_level','7'),
(6,2,'nickname','editor'),
(7,3,'wp_capabilities','a:1:{s:6:\"editor\";b:1;}'),
(8,3,'wp_user_level','7'),
(9,3,'nickname','dbadmin');

-- Options table (site configuration)
CREATE TABLE IF NOT EXISTS `wp_options` (
  `option_id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `option_name` varchar(191) NOT NULL,
  `option_value` longtext NOT NULL,
  `autoload` varchar(20) NOT NULL,
  PRIMARY KEY (`option_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `wp_options` VALUES
(1,'siteurl','http://dmz-web01.local/blog','yes'),
(2,'home','http://dmz-web01.local/blog','yes'),
(3,'blogname','DMZ-WEB01 Internal Blog','yes'),
(4,'blogdescription','Corporate Internal Communications','yes'),
(5,'users_can_register','0','yes'),
(6,'admin_email','admin@dmz-web01.local','yes'),
(7,'timezone_string','America/New_York','yes'),
(8,'date_format','F j, Y','yes'),
(9,'time_format','g:i a','yes');
