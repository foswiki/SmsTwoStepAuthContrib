# See bottom of file for license and copyright information

=begin TML

---+ package Foswiki::LoginManager::SmsTwoStepLogin

This is a login manager that you can specify in the security setup section of
[[%SCRIPTURL{"configure"}%][configure]]. It provides users with a
template-based form to enter usernames and passwords, and works with the
PasswordManager that you specify to verify those passwords.

Subclass of Foswiki::LoginManager; see that class for documentation of the
methods of this class.

=cut

package Foswiki::LoginManager::SmsTwoStepLogin;

use strict;
use warnings;
use Assert;
use Unicode::Normalize;

use Foswiki::LoginManager                ();
use Foswiki::LoginManager::TemplateLogin ();
our @ISA = ('Foswiki::LoginManager::TemplateLogin');
use Encode ();

# SMELL:  Why?
our $sessionVarName = '_SmsTwoStepAuthAccessCode';

BEGIN {
    if ( $Foswiki::cfg{UseLocale} ) {
        require locale;
        import locale();
    }
}

=begin TML

---++ ObjectMethod login( $query, $session )

If a login name and password have been passed in the query, it
validates these and if authentic, redirects to the original
script. If there is no username in the query or the username/password is
invalid (validate returns non-zero) then it prompts again.

If a flag to remember the login has been passed in the query, then the
corresponding session variable will be set. This will result in the
login cookie being preserved across browser sessions.

The password handler is expected to return a perl true value if the password
is valid. This return value is stored in a session variable called
VALIDATION. This is so that password handlers can return extra information
about the user, such as a list of Wiki groups stored in a separate
database, that can then be displayed by referring to
%<nop>SESSION_VARIABLE{"VALIDATION"}%

=cut

sub login {
    my ( $this, $query, $session ) = @_;
    my $users = $session->{users};

    my $origin = $query->param('foswiki_origin');
    my ( $origurl, $origmethod, $origaction ) =
      Foswiki::LoginManager::TemplateLogin::_unpackRequest($origin);
    my $loginName  = $query->param('username');
    my $loginPass  = $query->param('password');
    my $remember   = $query->param('remember');
    my $accessCode = $query->param('accesscode');

    #print STDERR Data::Dumper::Dumper( \$query );

    return $this->SUPER::login( $query, $session )
      if ( $loginName && $loginName eq $Foswiki::cfg{AdminUserLogin} );

    # UserMappings can over-ride where the login template is defined
    my $loginTemplate = $users->loginTemplateName();    #defaults to login.tmpl
    my $tmpl = Foswiki::Func::readTemplate($loginTemplate);

    my $banner = $session->templates->expandTemplate('LOG_IN_BANNER');
    my $note   = '';
    my $topic  = $session->{topicName};
    my $web    = $session->{webName};

    # CAUTION:  LoginManager::userLoggedIn() will delete and recreate
    # the CGI Session.
    # Do not make a local copy of $this->{_cgisession}, or it will point
    # to a deleted session once the user has been logged in.

    if (   $this->{_cgisession}
        && $this->{_cgisession}->param('AUTHUSER')
        && $loginName
        && $loginName ne $this->{_cgisession}->param('AUTHUSER') )
    {
        $banner = $session->templates->expandTemplate('LOGGED_IN_BANNER');
        $note   = $session->templates->expandTemplate('NEW_USER_NOTE');
    }

    my $error = '';

    if ($loginName) {
        my $validation = $users->checkPassword( $loginName, $loginPass );
        $error = $users->passwordError($loginName);

        if (  !$validation
            && $Foswiki::cfg{TemplateLogin}{AllowLoginUsingEmailAddress}
            && ( $loginName =~ $Foswiki::regex{emailAddrRegex} ) )
        {

            # try email addresses if it is one
            my $cuidList = $users->findUserByEmail($loginName);
            foreach my $cuid (@$cuidList) {
                my $login = $users->getLoginName($cuid);

                $validation = $users->checkPassword( $login, $loginPass );
                if ($validation) {
                    $loginName = $login;
                    last;
                }
            }
        }

        print STDERR "2-Step: user/pass verified\n" if $validation;

        if ( $validation && $accessCode ) {

       # received access code, verify it for second challenge on two-factor auth
            $banner = $this->verifyAuth( $session, $loginName, $accessCode );
            $validation = 0 if ($banner);

            # Eat these so there's no risk of accidental passthrough
            $query->delete( 'foswiki_origin', 'username', 'password',
                'accesscode' );
        }
        elsif ($validation) {

            # Password validated, present second challenge on two-factor auth
            $tmpl = $this->secondStepAuth( $session, $loginName, $origurl );
            $validation = 0 if ($tmpl);

        }
        else {
            # Tasks:Item1029  After much discussion, the 403 code is not
            # used for authentication failures. RFC states: "Authorization
            # will not help and the request SHOULD NOT be repeated" which
            # is not the situation here.
            $session->{response}->status(200);
            $session->logger->log(
                {
                    level    => 'info',
                    action   => 'login',
                    webTopic => $web . '.' . $topic,
                    extra    => "AUTHENTICATION FAILURE - $loginName - ",
                }
            );
            $banner = $session->templates->expandTemplate('UNRECOGNISED_USER');

            # Eat these so there's no risk of accidental passthrough
            $query->delete( 'foswiki_origin', 'username', 'password',
                'accesscode' );
        }

        if ($validation) {

            # SUCCESS our user is authenticated. Note that we may already
            # have been logged in by the userLoggedIn call in loadSession,
            # because the username-password URL params are the same as
            # the params passed to this script, and they will be used
            # in loadSession if no other user info is available.
            $this->userLoggedIn($loginName);
            $session->logger->log(
                {
                    level    => 'info',
                    action   => 'login',
                    webTopic => $web . '.' . $topic,
                    extra    => "AUTHENTICATION SUCCESS - $loginName - "
                }
            );

            # remove the sudo param - its only to tell TemplateLogin
            # that we're using BaseMapper..
            $query->delete('sudo');

            $this->{_cgisession}->param( 'VALIDATION', $validation )
              if $this->{_cgisession};
            if ( !$origurl || $origurl eq $query->url() ) {
                $origurl = $session->getScriptUrl( 0, 'view', $web, $topic );
            }
            else {

                # Unpack params encoded in the origurl and restore them
                # to the query. If they were left in the query string they
                # would be lost if we redirect with passthrough.
                # First extract the params, ignoring any trailing fragment.
                if ( $origurl =~ s/\?([^#]*)// ) {
                    foreach my $pair ( split( /[&;]/, $1 ) ) {
                        if ( $pair =~ m/(.*?)=(.*)/ ) {
                            $query->param( $1, TAINT($2) );
                        }
                    }
                }

                # Restore the action too
                $query->action($origaction) if $origaction;
            }

            # Restore the method used on origUrl so if it was a GET, we
            # get another GET.
            $query->method($origmethod);
            $session->redirect( $origurl, 1 );
            return;
        }

        #else {

        # Tasks:Item1029  After much discussion, the 403 code is not
        # used for authentication failures. RFC states: "Authorization
        # will not help and the request SHOULD NOT be repeated" which
        # is not the situation here.
        #    $session->{response}->status(200);
        #    $session->logger->log(
        #        {
        #            level    => 'info',
        #            action   => 'login',
        #            webTopic => $web . '.' . $topic,
        #            extra    => "AUTHENTICATION FAILURE - $loginName - ",
        #        }
        #    );
        #    $banner = $session->templates->expandTemplate('UNRECOGNISED_USER');
        #}

    }
    else {

        # If the loginName is unset, then the request was likely a perfectly
        # valid GET call to http://foswiki/bin/login
        # 4xx cannot be a correct status, as we want the user to retry the
        # same URL with a different login/password
        $session->{response}->status(200);
    }

    # Remove the validation_key from the *passed through* params. It isn't
    # required, because the form will have a new validation key, and
    # giving the parameter twice will confuse the strikeone Javascript.
    $session->{request}->delete('validation_key');

    # set the usernamestep value so it can be re-displayed if we are here due
    # to a failed authentication attempt.
    $query->param( -name => 'usernamestep', -value => $loginName );

    # TODO: add JavaScript password encryption in the template
    $origurl ||= '';

    # Truncate the path_info at the first quote
    my $path_info = $query->path_info();
    if ( $path_info =~ m/['"]/g ) {
        $path_info = substr( $path_info, 0, ( ( pos $path_info ) - 1 ) );
    }

    # Set session preferences that will be expanded when the login
    # template is instantiated
    $session->{prefs}->setSessionPreferences(
        FOSWIKI_ORIGIN => Foswiki::entityEncode(
            Foswiki::LoginManager::TemplateLogin::_packRequest(
                $origurl, $origmethod, $origaction
            )
        ),

        # Path to be used in the login form action.
        # Could have used %ENV{PATH_INFO} (after extending {AccessibleENV})
        # but decided against it as the path_info might have been rewritten
        # from the original env var.
        PATH_INFO =>
          Foswiki::urlEncode( NFC( Foswiki::decode_utf8($path_info) ) ),
        BANNER => $banner,
        NOTE   => $note,
        ERROR  => $error
    );

    my $topicObject = Foswiki::Meta->new( $session, $web, $topic );
    $tmpl = $topicObject->expandMacros($tmpl);
    $tmpl = $topicObject->renderTML($tmpl);
    $tmpl =~ s/<nop>//g;
    $session->writeCompletePage($tmpl);
}

=begin TML

---++ ObjectMethod secondStepAuth()

Do second step authentication:

   * Send user an SMS with one time access code
   * Show dialog to enter access code

=cut

sub secondStepAuth {

    my ( $this, $session, $loginName, $origUrl ) = @_;
    $origUrl ||= '';
    my $wikiName = $session->{users}->getWikiName($loginName);
    my $debug    = $Foswiki::cfg{SmsTwoStepAuthContrib}{Debug};
    my $debugID  = "Foswiki::LoginManager::SmsTwoStepAuth::secondStepAuth";

    print STDERR "2-Step: secondStepAuth called\n";

    # skip second auth if in command line context
    return '' if $session->inContext('command_line');

    my $topicObject =
      Foswiki::Meta->load( $session, $Foswiki::cfg{UsersWebName}, $wikiName );

    my @addresses;

    # Try the form first
    my $entry = $topicObject->get( 'FIELD', 'Email' );

    # check two-step auth mode
    my $twoStepAuth = $Foswiki::cfg{SmsTwoStepAuthContrib}{TwoStepAuth}
      || 'required';
    if ( $twoStepAuth eq 'disabled' ) {
        Foswiki::Func::writeDebug(
            "$debugID: Two-step auth disabled for all users")
          if ($debug);
        return '';    # use single setp auth

    }
    elsif ( $twoStepAuth eq 'optional' ) {
        my $field = $topicObject->get( 'FIELD', 'TwoStepAuth' );
        unless ( $field && Foswiki::Func::isTrue( $field->{value} ) ) {
            Foswiki::Func::writeDebug(
                "$debugID: $wikiName opted out of two-step auth")
              if ($debug);
            return '';    # user did not opt in for two-step auth
        }

    }
    else {
        # else continue, two-step auth is required
    }

    # check whitelist
    #SMELL: Does not support IPv6
    #
    my $addr = $session->{request}->remoteAddress() || '';
    my $whitelist = $Foswiki::cfg{SmsTwoStepAuthContrib}{WhitelistAddresses}
      || '';
    $whitelist =~ s/[^0-9\.\,]//g;
    $whitelist =~ s/,/\|/g;
    if ( $addr && $whitelist && $addr =~ /^($whitelist)/ ) {

        # trusted environment, skip second step authentication
        Foswiki::Func::writeDebug(
            "$debugID: Whitelisted IP for $wikiName, single step auth")
          if ($debug);
        return '';
    }

    # two-step authentication is required - generate one-time-use access code
    my $accessCode = 'ac'
      . sprintf( '%02d', rand(100) ) . '-'
      . sprintf( '%04d', rand(10000) );

    # initialize variables
    my $allowEmail = $Foswiki::cfg{SmsTwoStepAuthContrib}{AllowEmail} || '';
    my $messageTemplate = $Foswiki::cfg{SmsTwoStepAuthContrib}{SmsMessageTmpl}
      || 'smstwostepmessage';
    my $dialogTemplate = $Foswiki::cfg{SmsTwoStepAuthContrib}{SmsLoginTmpl}
      || 'smstwosteplogin';
    my $mobile       = '';
    my $carrier      = '';
    my $email        = '';
    my $filter       = '';
    my $authPossible = 1;

    # get mobile number and carrier
    my $field = $topicObject->get( 'FIELD', 'Email' );
    $email = $field->{value} if ($field);
    $field = $topicObject->get( 'FIELD', 'Mobile' );
    $mobile = $field->{value} if ($field);
    $field = $topicObject->get( 'FIELD', 'MobileCarrier' );
    $carrier = $field->{value} if ($field);

# get gateway e-mail from mobile carrier table row based on user's Mobile Carrier field
    my ( $meta, $text ) =
      Foswiki::Func::readTopic( $Foswiki::cfg{SystemWebName},
        'SmsTwoStepAuthContrib' );

    # Example mobile carrier table row:
    #   | *Type* | *Carrier* | *E-mail* | *Filter* | *Activation* |
    #   | E2SMS | USA: AT&T | $phone@txt.att.net | ^\+?1? | |
    my $gatewayEmail = '';
    if (   $carrier
        && $text =~ /.*E2SMS *\| *$carrier *\| *(.*?) *\| *(.*?) *\|/ )
    {
        $gatewayEmail = $1;
        $filter       = $2;
    }

    # compose SMS e-mail address from Mobile field and from gateway e-mail
    if ( $mobile && $carrier && $gatewayEmail ) {
        $mobile       =~ s/$filter//;
        $mobile       =~ s/[^0-9]//g;
        $gatewayEmail =~ s/\$phone/$mobile/g;
        $email = $gatewayEmail;

    }
    elsif ( $allowEmail eq '1'
        || ( $allowEmail && grep { /^$wikiName$/ } split( /, */, $allowEmail ) )
      )
    {
        # send to user's registered e-mail address
        my @emails =
          map { my $a = "$wikiName <$_>"; $a; }
          $session->{users}->getEmails($loginName);
        if ( scalar @emails ) {

          # use system e-mail, overriding Email form field on user profile topic
            $email = join( ', ', @emails );
        }
        else {
            # system e-mail not available, use e-mail on user profile topic
            $email = "$wikiName <$email>";
        }
        $messageTemplate =
          $Foswiki::cfg{SmsTwoStepAuthContrib}{EmailMessageTmpl}
          || 'smstwostepemailmessage';
        $dialogTemplate = $Foswiki::cfg{SmsTwoStepAuthContrib}{EmailLoginTmpl}
          || 'smstwostepemaillogin';

    }
    else {
        # insufficient credentials, user can't log in
        $authPossible   = 0;
        $dialogTemplate = $Foswiki::cfg{SmsTwoStepAuthContrib}{ErrorLoginTmpl}
          || 'smstwosteperrorlogin';
    }
    if ($debug) {
        Foswiki::Func::writeDebug( "$debugID debug for $wikiName:\n"
              . "allowEmail: $allowEmail\n"
              . "messageTemplate: $messageTemplate\n"
              . "dialogTemplate: $dialogTemplate\n"
              . "mobile: $mobile\n"
              . "carrier: $carrier\n"
              . "email: $email\n"
              . "filter: $filter\n"
              . "authPossible: $authPossible" );
    }

  # SMELL: Foswiki won't necessarily have a session until the login is complete.
  # We shouild have the data in the tmp directory.
  # save access code for later verification
    my $now = time();
    Foswiki::Func::setSessionValue( $sessionVarName,
        "$accessCode:$now:$loginName" );

    # send e-mail to log-in user with access code
    if ($authPossible) {
        my $tmpl =
          Foswiki::Func::readTemplate( $messageTemplate, $session->getSkin() );
        return
"Two-step authentication installation error: $messageTemplate template not found"
          unless ($tmpl);
        $tmpl =~ s/%EMAILADDRESS%/$email/geo;
        $tmpl =~ s/%ACCESSCODE%/$accessCode/go;
        $tmpl =
          Foswiki::Func::expandCommonVariables( $tmpl, $session->{webName},
            $session->{topicName} );
        $tmpl =~ s/<nop>//g;
        if ($debug) {
            Foswiki::Func::writeDebug("$debugID e-mail:");
            Foswiki::Func::writeDebug("===( START )=============");
            Foswiki::Func::writeDebug("$tmpl");
            Foswiki::Func::writeDebug("===(  END  )=============");
        }
        my $warnings = Foswiki::Func::sendEmail($tmpl);

        return "$warnings <hr /><pre>$tmpl</pre>" if ($warnings);
    }

    # load and return "enter access code" template
    my $tmpl =
      Foswiki::Func::readTemplate( $dialogTemplate, $session->getSkin() )
      || "Two-step authentication installation error: $dialogTemplate template not found";
    $tmpl =~ s/%LOGINNAME%/$loginName/go;
    $tmpl =~ s/%ORIGURL%/$origUrl/go;
    return $tmpl;
}

=pod

---++ ObjectMethod verifyAuth()

Verify access code on second step authentication. Return empty string if OK, else return error string.

=cut

sub verifyAuth {
    my ( $this, $session, $loginName, $accessCode ) = @_;
    my $debug   = $Foswiki::cfg{SmsTwoStepAuthContrib}{Debug};
    my $debugID = "Foswiki::LoginManager::SmsTwoStepAuth::verifyAuth";

    return '' if $session->inContext('command_line');

    # compare to saved access code
    my ( $expectedAC, $timestamp, $expectedLN ) =
      split( /:/, Foswiki::Func::getSessionValue($sessionVarName), 3 );
    Foswiki::Func::clearSessionValue($sessionVarName)
      ;    # clear session variable (one time use only)
    my $maxAge = $Foswiki::cfg{SmsTwoStepAuthContrib}{MaxAge} || 600;
    my $error = '';
    print STDERR
"Verify:  AC: $accessCode  Expected: $expectedAC LN: $loginName Expected: $expectedLN TS $timestamp+$maxAge > "
      . time() . "\n";
    unless ( $accessCode
        && ( $accessCode eq $expectedAC )
        && ( $loginName  eq $expectedLN )
        && $timestamp + $maxAge > time() )
    {
        $error = $Foswiki::cfg{SmsTwoStepAuthContrib}{AcessCodeError}
          || 'Invalid or outdated access code, please try again';
    }
    if ( $Foswiki::cfg{SmsTwoStepAuthContrib}{Debug} ) {
        Foswiki::Func::writeDebug(
            "Foswiki::LoginManager::SmsTwoStepAuth::verifyAuth return: '$error'"
        );
    }
    return $error;
}

1;
__END__
Module of Foswiki - The Free and Open Source Wiki, http://foswiki.org/

Copyright (C) 2008-2017 Foswiki Contributors. All Rights Reserved.
Foswiki Contributors are listed in the AUTHORS file in the root
of this distribution. NOTE: Please extend that file, not this notice.

Additional copyrights apply to some or all of the code in this
file as follows:

Copyright (C) 2014 Wave Systems Corp.
Copyright (C) 2014-2016 Peter Thoeny, peter[at]thoeny.org
Copyright (C) 2014-2016 TWiki Contributors. All Rights Reserved.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 3
of the License, or (at your option) any later version. For
more details read LICENSE in the root of this distribution.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

As per the GPL, removal of this notice is prohibited.
