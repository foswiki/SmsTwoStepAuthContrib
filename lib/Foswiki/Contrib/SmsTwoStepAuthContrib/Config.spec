# ---+ Extensions
# ---++ SMS Two-Step Auth Contrib
# This is the configuration of the <b>SmsTwoStepAuthContrib</b>.

# **STRING 80**
# White-listed IP addresses. Specify a comma-space separated list. Partial IP addresses
# ending in a dot can be used to specify a range. Example: <tt>1.2.3.4, 5.6.7.</tt>
$Foswiki::cfg{SmsTwoStepAuthContrib}{WhitelistAddresses} = '';

# **NUMBER**
# Maximum age of access code in seconds, default is 600 (10 min).
$Foswiki::cfg{SmsTwoStepAuthContrib}{MaxAge} = 600;

# **SELECT off, optional, required**
# Mode of two-step authentication:
# <ul>  <li> <tt>disabled</tt>: Single step authentication.
# </li> <li> <tt>optional</tt>: Optional, e.g. user can chose. <b><i>Attention:</i></b>
# The UserForm and UserProfileHeader need to be updated - see installation instructions.
# </li> <li> <tt>required</tt>: Required for all users. (default)
# </li> </ul>
$Foswiki::cfg{SmsTwoStepAuthContrib}{TwoStepAuth} = 'required';

# **STRING 80**
# It is possible to send the access code by e-mail instead of SMS if the user has not
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

# **STRING 80**
# Name of two-step message template for SMS message, default 'smstwostepmessage'.
$Foswiki::cfg{SmsTwoStepAuthContrib}{SmsMessageTmpl} = 'smstwostepmessage';

# **STRING 80**
# Name of log-in screen template for SMS log-in, default 'smstwosteplogin'.
$Foswiki::cfg{SmsTwoStepAuthContrib}{SmsLoginTmpl} = 'smstwosteplogin';

# **STRING 80**
# Name of two-step message template for e-mail message, default 'smstwostepemailmessage'.
$Foswiki::cfg{SmsTwoStepAuthContrib}{EmailMessageTmpl} = 'smstwostepemailmessage';

# **STRING 80**
# Name of log-in screen template for e-mail log-in, default 'smstwostepemaillogin'.
$Foswiki::cfg{SmsTwoStepAuthContrib}{EmailLoginTmpl} = 'smstwostepemaillogin';

# **STRING 80**
# Name of log-in screen template in case of insufficient credentials, default 'smstwosteperrorlogin'.
$Foswiki::cfg{SmsTwoStepAuthContrib}{ErrorLoginTmpl} = 'smstwosteperrorlogin';

# **STRING 80**
# Access code error message.
$Foswiki::cfg{SmsTwoStepAuthContrib}{AcessCodeError} = 'Invalid or outdated access code, please try again.';

# **BOOLEAN**
# Debug flag - see output in <code>twiki/data/debug.txt</code>.
$Foswiki::cfg{SmsTwoStepAuthContrib}{Debug} = 0;

1;
