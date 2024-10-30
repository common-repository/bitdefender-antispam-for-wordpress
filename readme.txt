=== Bitdefender Antispam ===
Contributors: bitdefender
Tags: comments, spam
Requires at least: 2.7.1
Tested up to: 3.1.3
Stable tag: trunk

BitDefender 4 Blogs is one of our newest solutions to fight spam... on blogs.

== Description ==

You probably already know that 9 out of 10 email messages are spam, but did you know that almost 8 out of 10 blog comments are spam? At this very moment, there is no spam free communication platform, and every day we see how spammers and malware writers expand their territories and conquer new communication environments.
 
This is why we, at BitDefender, are doing extensive research on comment related spam and we're glad to offer this solution to the bloggers. It's fresh out of a fairly extensive closed beta where it ran, collected, analyzed and filtered a huge amount of comments on a few hundred selected blogs and we got the engines to a really competitive level, ready for you to test and use.
 
We don’t believe we are perfect, but we are, however, tweaking the engines and tuning our technology with every feedback we receive. 
 
As of Dec 2nd, BitDefender 4blogs is officially in public BETA and you can install it with a few clicks either by downloading the plug-in from our website or through the WP plug-ins repository. We appreciate all feedback so don't hesitate to get in touch with us.
 
For further information about the technology, you can either check our website at http://4blogs.bitdefender.com or directly email us at 4blogs@bitdefender.com.

== Installation ==

1. from WordPress Dashboard/Plugins select Add New
2. select Upload and browse to the plugin
3. install and activate
4. enter a valid e-mail in the BitDefender Client ID field

If unsuccessful, try uploading the plugin by ftp in the plugin directory(wp-content/plugins) and activate manually.
This section describes how to install the plugin and get it working.


== Changelog ==

= 1.3.1 =
* Bug fix: When using rescan, if moderation is activated legit comments are hold on moderation queue

= 1.3 =
* Support for Network Activation in WP multisite

= 1.2.2 =
* Option to mark as spam comments at posts older than 30 days.
* Option to moderate comments on scan error.

= 1.2.1 =
* Retry comment rescanning in case of error.
* Send statistics in cloud about failed scans
* Send statistics in cloud about plugin activation/deactivation.
* Removed unused includes in bd-js.php file.

= 1.2 =
* Comment rescanning option for individual comments.
* Feature to whitelist IPs.
* Improved comment formatting in log interface.
* Comment rescanning interface for multiple comments.

= 1.1 =
* The [Bitdefender Spam] mark is displayed only in administrative interface

= 1.0 =
* Bug regarding bd_plugin_path on Windows fixed.
* Switched to the new cloud protocol.
* Changed the "Powered by" picture.
* Redesigned interface.

= 0.7 =
* Bug regarding "Empty delimiter" warning fixed.
* "Powered by" widget.

= 0.6 =
* Bug regarding site_url() fixed.
* Bug at IP blacklisting fixed.
* Option to blackist IP-s in comments page.
* User action confirmtion (saving options, etc).

= 0.5 =
* New spam related settings: charset filters and aggresivity level.
* Removed buggy message at comment deletion.
* Menus moved on top of pages.

= 0.4 =
* The spam caught by Bitdefender is tagged.
* New page with Bitdefender Stats.

= 0.3 =
* Report blacklisted IP-s
* Option for chooing language
* Rescaning feature: in case of server error, unscanned comments are rescanned latter.
* In case of server error, displays correct error message, and puts the comment in moderation queue.

= 0.2 =
* Fix the log interface for older Wordpress versions(2.2.2)

= 0.1 =
* Initial release

== Upgrade Notice ==

= 0.5 =
* Deactivate and delete the old plugin. Reinstall the 0.5 plugin from Wordpress Dashboard/Plugins.

= 0.4 =
* Deactivate and delete the old plugin. Reinstall the 0.4 plugin from Wordpress Dashboard/Plugins.

= 0.3 =
* In case of server error, comments are moderated.
* You need do deactivate and activate again the plugin after upgrade.

= 0.2 =
* This version fixes the log interface for older Wordpress versions(2.2.2).

 

