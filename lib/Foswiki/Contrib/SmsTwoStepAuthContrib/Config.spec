#---+ Security and Authentication
#---++ Login

# **STRING 80 LABEL="White List Addresses" DISPLAY_IF="{LoginManager}=='Foswiki::LoginManager::SmsTwoStepLogin'" **
# White-listed IP addresses that can bypass 2-step authentication. Specify a comma-space separated list. Partial IP addresses
# ending in a dot can be used to specify a range. Example: <tt>1.2.3.4, 5.6.7.</tt>
$Foswiki::cfg{SmsTwoStepAuthContrib}{WhitelistAddresses} = '';

# **NUMBER LABEL="Access Code Lifetime" DISPLAY_IF="{LoginManager}=='Foswiki::LoginManager::SmsTwoStepLogin'"**
# Maximum age of access code in seconds, default is 600 (10 min).
$Foswiki::cfg{SmsTwoStepAuthContrib}{MaxAge} = 600;

# **SELECT off,optional,required LABEL="Two Step Authentication" DISPLAY_IF="{LoginManager}=='Foswiki::LoginManager::SmsTwoStepLogin'"**
# Mode of two-step authentication:
# <ul>  <li> <tt>disabled</tt>: Single step authentication.
# </li> <li> <tt>optional</tt>: Optional, e.g. user can chose. <b><i>Attention:</i></b>
# The UserForm and User Registration forms may need to be updated - see installation instructions.
# </li> <li> <tt>required</tt>: Required for all users. (default)
# </li> </ul>
$Foswiki::cfg{SmsTwoStepAuthContrib}{TwoStepAuth} = 'required';

# **STRING 80 LABEL="Allow Email Fallback" DISPLAY_IF="{LoginManager}=='Foswiki::LoginManager::SmsTwoStepLogin'"**
# Allow the access code to be sent by Email instead of SMS if the user has not
# specified a mobile number and a carrier. Possible values:
# <ul>  <li> <tt>0</tt> or empty value: No e-mail sent, user cannot login (more secure).
# </li> <li> <tt>1</tt>: Users with missing mobile and carrier get an e-mail with access
# code (more flexible).
# </li> <li> List of users: Specify a comma-space separated list of WikiWord names of
# users who can get an e-mail. Examples:
# <br /> <tt>JimmyNeutron</tt> - only one specified user
# <br /> <tt>JimmyNeutron, DonaldDuck</tt> - only two specified users
# </li> </ul>
$Foswiki::cfg{SmsTwoStepAuthContrib}{AllowEmail} = '';

# **STRING 80 EXPERT**
# Name of two-step message template for SMS message, default 'smstwostepmessage'.
$Foswiki::cfg{SmsTwoStepAuthContrib}{SmsMessageTmpl} = 'smstwostepmessage';

# **STRING 80 EXPERT**
# Name of log-in screen template for SMS log-in, default 'smstwosteplogin'.
$Foswiki::cfg{SmsTwoStepAuthContrib}{SmsLoginTmpl} = 'smstwosteplogin';

# **STRING 80 EXPERT**
# Name of two-step message template for e-mail message, default 'smstwostepemailmessage'.
$Foswiki::cfg{SmsTwoStepAuthContrib}{EmailMessageTmpl} = 'smstwostepemailmessage';

# **STRING 80 EXPERT**
# Name of log-in screen template for e-mail log-in, default 'smstwostepemaillogin'.
$Foswiki::cfg{SmsTwoStepAuthContrib}{EmailLoginTmpl} = 'smstwostepemaillogin';

# **STRING 80 EXPERT**
# Name of log-in screen template in case of insufficient credentials, default 'smstwosteperrorlogin'.
$Foswiki::cfg{SmsTwoStepAuthContrib}{ErrorLoginTmpl} = 'smstwosteperrorlogin';

# **STRING 80 EXPERT**
# Access code error message.
$Foswiki::cfg{SmsTwoStepAuthContrib}{AcessCodeError} = 'Invalid or outdated access code, please try again.';

# **BOOLEAN EXPERT**
# Debug flag - see output in <code>foswiki/working/logs/debug.log</code>.
$Foswiki::cfg{SmsTwoStepAuthContrib}{Debug} = 0;

1;
