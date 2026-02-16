<?php
/**
 *  ------------------------------------------------------------------------
 *  GLPISaml
 *
 *  GLPISaml was inspired by the initial work of Derrick Smith's
 *  PhpSaml. This project's intend is to address some structural issues
 *  caused by the gradual development of GLPI and the broad amount of
 *  wishes expressed by the community.
 *
 *  Copyright (C) 2024 by Chris Gralike
 *  ------------------------------------------------------------------------
 *
 * LICENSE
 *
 * This file is part of GLPISaml project.
 *
 * GLPISaml plugin is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * GLPISaml is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with GLPISaml. If not, see <http://www.gnu.org/licenses/> or
 * https://choosealicense.com/licenses/gpl-3.0/
 *
 * ------------------------------------------------------------------------
 *
 *  @package    GLPISaml
 *  @version    1.1.12
 *  @author     Chris Gralike
 *  @copyright  Copyright (c) 2024 by Chris Gralike
 *  @license    GPLv3+
 *  @see        https://github.com/DonutsNL/GLPISaml/readme.md
 *  @link       https://github.com/DonutsNL/GLPISaml
 *  @since      1.0.0
 * ------------------------------------------------------------------------
 **/

namespace GlpiPlugin\Glpisaml\LoginFlow;

use Session;
use Group_User;
use Profile_User;
use User as glpiUser;
use Glpi\Toolbox\Sanitizer;
use OneLogin\Saml2\Response;
use GlpiPlugin\Glpisaml\LoginFlow;
use GlpiPlugin\Glpisaml\LoginState;
use GlpiPlugin\Glpisaml\RuleSamlCollection;
use GlpiPlugin\Glpisaml\Config\ConfigEntity;

/**
 * This class is responsible to make sure a corresponding
 * user is returned after successful login. If a user does
 * not exist it will create one if JIT is enabled else it will
 * trigger a human readable error. On Jit creation it will also
 * call the RuleSamlCollection and parse any configured rules.
 */
class User
{
    // Common user/group/profile constants
    public const USERID = 'id';
    public const NAME = 'name';
    public const REALNAME = 'realname';
    public const FIRSTNAME = 'firstname';
    public const EMAIL = '_useremails';
    public const MOBILE = 'mobile';
    public const PHONE = 'phone';
    public const PHONE2 = 'phone2';
    public const COMMENT = 'comment';
    public const PASSWORD = 'password';
    public const PASSWORDN = 'password2';
    public const DELETED = 'is_deleted';
    public const ACTIVE = 'is_active';
    public const RULEOUTPUT = 'output';
    public const USERSID = 'users_id';
    public const GROUPID = 'groups_id';
    public const GROUP_DEFAULT = 'specific_groups_id';
    public const IS_DYNAMIC = 'is_dynamic';
    public const PROFILESID = 'profiles_id';
    public const PROFILE_DEFAULT = '_profiles_id_default';
    public const PROFILE_RECURSIVE = 'is_recursive';
    public const ENTITY_ID = 'entities_id';
    public const ENTITY_DEFAULT = '_entities_id_default';
    public const AUTHTYPE = 'authtype';
    public const SYNCDATE = 'date_sync';  //Y-m-d H:i:s
    public const SAMLGROUPS = 'samlClaimedGroups';
    public const SAMLJOBTITLE = 'samlClaimedJobTitle';
    public const SAMLCOUNTRY = 'country';
    public const SAMLCITY = 'city';
    public const SAMLSTREET = 'street';


    /**
     * samlResponse attributes or claims provided by IdP.
     * @see https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
     * @see https://learn.microsoft.com/en-us/entra/identity-platform/reference-saml-tokens
     */
    public const USERDATA = 'userData';
    public const SCHEMA_NAMEID = 'NameId';                                                                // Used to match users in GLPI.
    public const SCHEMA_SURNAME = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname';         // Used in user creation JIT - Optional
    public const SCHEMA_FIRSTNAME = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/firstname';       // Used in user creation JIT - Optional
    public const SCHEMA_GIVENNAME = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname';       // Used in user creation JIT - Optional
    public const SCHEMA_EMAILADDRESS = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress';    // Used in user creation JIT - Required
    public const SCHEMA_MOBILE = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/mobilephone';     // Used in user creation JIT - Optional
    public const SCHEMA_PHONE = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/telephonenumber'; // Used in user creation JIT - Optional
    public const SCHEMA_JOBTITLE = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/jobtitle';        // Used in user creation JIT - Optional
    public const SCHEMA_COUNTRY = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/country';         //
    public const SCHEMA_CITY = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/city';            //
    public const SCHEMA_STREET = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/streetaddress';   //
    public const SCHEMA_GROUPS = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups';        // Used in assignment rules - Optional
    public const SCHEMA_NAME = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name';            // Entra claim not used
    public const SCHEMA_TENANTID = 'http://schemas.microsoft.com/identity/claims/tenantid';                 // Entra claim not used
    public const SCHEMA_OBJECTID = 'http://schemas.microsoft.com/identity/claims/objectidentifier';         // Entra claim not used
    public const SCHEMA_DISPLAYNAME = 'http://schemas.microsoft.com/identity/claims/displayname';              // Entra claim not used
    public const SCHEMA_IDP = 'http://schemas.microsoft.com/identity/claims/identityprovider';         // Entra claim not used
    public const SCHEMA_AUTHMETHODSREF = 'http://schemas.microsoft.com/claims/authnmethodsreferences';            // Entra claim not used
    public const SCHEMA_WIDS = 'http://schemas.microsoft.com/ws/2008/06/identity/claims/wids';          // Entra claim not used

    /**
     * Gets or creates (if JIT is enabled for IDP) the GLPI user.
     *
     * @param   array       Containing user attributes found in Saml claim
     * @return  glpiUser    GlpiUser object with populated fields.
     * @since               1.0.0
     */
    public function getOrCreateUser(array $userFields): glpiUser    //NOSONAR Complexity by design
    {
        // At this point the userFields should be present and validated (textually) by loginFlow.
        // https://codeberg.org/QuinQuies/glpisaml/issues/71
        // Load GLPI user object
        $user = new glpiUser();
        $name = (array_key_exists(User::NAME, $userFields) && isset($userFields[User::NAME])) ? $userFields[User::NAME] : '';
        $email = (array_key_exists(User::EMAIL, $userFields) && isset($userFields[User::EMAIL][0])) ? $userFields[User::EMAIL][0] : '';


        // Verify if user exists in database.
        // https://codeberg.org/QuinQuies/glpisaml/issues/48
        if (
            !$user->getFromDBbyName($name) &&      // Try to locate by name->NameId, continue on ! fail.
            !$user->getFromDBbyEmail($email) &&      // Try to locate by email->emailaddress, continue on ! fail.
            !$user->getFromDBbyEmail($name)
        ) {      // Try to locate by email->emailaddress, continue on ! fail.
            // User is not found, do we need to create it?

            // Get current loginState and
            // Fetch the correct configEntity using the idp found in our loginState.
            if (!$configEntity = new ConfigEntity((new Loginstate())->getIdpId())) {
                LoginFlow::showLoginError(__("Your SSO login was successful but we where not able to fetch
                                              the loginState from the database and could not continue to log
                                              you into GLPI.", PLUGIN_NAME));
            }

            // Are we allowed to perform JIT user creation?
            if ($configEntity->getField(ConfigEntity::USER_JIT)) {

                // Build the input array using the provided attributes (claims)
                // from the samlResponse. maybe use this method in the future
                // to also validate provided claims in one go.
                if (!$id = $user->add(Sanitizer::sanitize($userFields))) {
                    LoginFlow::showLoginError(__("Your SSO login was successful but there is no matching GLPI user account and
                                                  we failed to create one dynamically using Just In Time user creation. Please
                                                  request a GLPI administrator to review the logs and correct the problem or
                                                  request the administrator to create a GLPI user manually.", PLUGIN_NAME));
                    // PHP0405-no return by design.
                } else {
                    $ruleCollection = new RuleSamlCollection();
                    $matchInput = [
                        User::EMAIL => $userFields[User::EMAIL],
                        User::SAMLGROUPS => $userFields[User::SAMLGROUPS],
                        User::SAMLJOBTITLE => $userFields[User::SAMLJOBTITLE],
                        User::SAMLCOUNTRY => $userFields[User::SAMLCOUNTRY],
                        User::SAMLCITY => $userFields[User::SAMLCITY],
                        User::SAMLSTREET => $userFields[User::SAMLSTREET]
                    ];
                    // Uses a hook to call $this->updateUser() if a rule was found.
                    $ruleCollection->processAllRules($matchInput, [User::USERSID => $id], []);
                }

                // Return freshly created user!
                $user = new glpiUser();
                if ($user->getFromDB($id)) {
                    Session::addMessageAfterRedirect('Dynamically created GLPI user for:' . $userFields[User::EMAIL]['0']);
                    return $user;
                }
            } else {
                // Show a nice login Error
                $idpName = $configEntity->getField(ConfigEntity::NAME);
                $email = $userFields[User::EMAIL]['0'];
                LoginFlow::showLoginError(__("Your SSO login was successful but there is no matching GLPI user account. In addition the Just-in-time user creation
                                              is disabled for: $idpName. Please contact your GLPI administrator and request an account to be created matching the
                                              provided email claim: $email or login using a local user account.", PLUGIN_NAME));
                // PHP0405-no return by design.
            }

            // User is found, check if we are allowed to use it.
        } else {
            // Verify the user is not deleted (in trashcan)
            if ($user->fields[User::DELETED]) {
                LoginFlow::showLoginError(__("User with GlpiUserid: " . $user->fields[User::USERID] . " is marked deleted but still exists in the GLPI database. Because of
                                           this we cannot log you in as this would violate GLPI its security policies. Please contact the GLPI administrator
                                           to restore the user with provided ID or purge the user to allow the Just in Time (JIT) user creation to create a
                                           new user with the idp provided claims.", PLUGIN_NAME));
                // PHP0405-no return by design.
            }
            // Verify the user is not disabled by the admin;
            if ($user->fields[User::ACTIVE] == 0) {
                LoginFlow::showLoginError(__("User with GlpiUserid: " . $user->fields[User::USERID] . " is disabled. Please contact your GLPI administrator and request him to
                                            reactivate your account.", PLUGIN_NAME));
                // PHP0405-no return by design.
            }
            // Return the user to the LoginFlow object for session initialization!.
            return $user;
        }
    }

    public function updateUserRights(array $params): void       //NOSONAR - Complexity by design
    {
        // We are working on the output only.
        $update = $params[User::RULEOUTPUT];
        // Do we need to add a group?
        if (
            isset($update[User::GROUPID]) &&
            isset($update[User::USERSID])
        ) {
            // Get the Group_User object to update the user group relation.
            $groupuser = new Group_User();
            if (
                !$groupuser->add([
                    User::USERSID => $update[User::USERSID],
                    User::GROUPID => $update[User::GROUPID]
                ])
            ) {
                Session::addMessageAfterRedirect(__('GLPI SAML was not able to assign the correct permissions to your user.
                                                     Please let an Administrator review them before using GLPI.', PLUGIN_NAME));
            }
        }

        // Do we need to add profiles
        // If no profiles_id and user_id is present we skip.
        if (
            isset($update[User::PROFILESID]) &&
            isset($update[User::USERSID])
        ) {
            // Set the user to update
            $rights[User::USERSID] = $update[User::USERSID];
            // Set the profile to rights assignment
            $rights[User::PROFILESID] = $update[User::PROFILESID];
            // Do we need to set a profile for a specific entity?
            if (isset($update[User::ENTITY_ID])) {
                $rights[User::ENTITY_ID] = $update[User::ENTITY_ID];
            }
            // Do we need to make the profile behave recursive?
            if (isset($update[User::PROFILE_RECURSIVE])) {
                $rights[User::PROFILE_RECURSIVE] = (isset($update[User::PROFILE_RECURSIVE])) ? '1' : '0';
            }
            // Delete all default profile assignments
            $profileUser = new Profile_User();
            if ($pid = $profileUser->getForUser($update[User::USERSID])) {
                foreach ($pid as $key => $data) {
                    $profileUser->delete(['id' => $key]);
                }
            }
            // Assign collected Rights
            $profileUser = new Profile_User();
            if (!$profileUser->add($rights)) {
                Session::addMessageAfterRedirect(__('GLPI SAML was not able to assign the correct permissions to your user.
                                                    Please let an Administrator review the user before using GLPI.', PLUGIN_NAME));
            }
        }

        // Do we need to update the user profile defaults?
        if (
            isset($update[User::GROUP_DEFAULT]) ||
            isset($update[User::ENTITY_DEFAULT]) ||
            isset($update[User::PROFILE_DEFAULT])
        ) {
            // Set the user Id.
            $userDefaults['id'] = $update['users_id'];
            // Do we need to set a default group?
            if (isset($update[User::GROUP_DEFAULT])) {
                $userDefaults[User::GROUPID] = $update[User::GROUP_DEFAULT];
            }
            // Do we need to set a specific default entity?
            if (isset($update[User::ENTITY_DEFAULT])) {
                $userDefaults[User::ENTITY_ID] = $update[User::ENTITY_DEFAULT];
            }
            // Do we need to set a specific profile?
            if (isset($update[User::PROFILE_DEFAULT])) {
                $userDefaults[User::PROFILESID] = $update[User::PROFILE_DEFAULT];
            }

            $user = new glpiUser();
            if (!$user->update($userDefaults)) {
                Session::addMessageAfterRedirect(__('GLPI SAML was not able to update the user defaults.
                                                     Please let an administrator review the user before using GLPI.', PLUGIN_NAME));
            }
        }
    }

    /**
     * This function figures out what the samlResponse provided claims are and
     * evaluates the values and assigns them to the UserArray that will be
     * passed to the Auth object in the loginFlow object. If a critical error
     * is found, processing is stopped and an error shown.
     *
     * @param    Response  Response object with the samlResponse attributes.
     * @param    int       $idpId ID of the IdP configuration to use for mapping.
     * @return   array     user->add input fields array with properties.
     * @since    1.0.0
     */
    public static function getUserInputFieldsFromSamlClaim(Response $response, int $idpId = 0): array     //NOSONAR - Complexity by design.
    {
        // Load configuration for the current IdP
        $config = new ConfigEntity($idpId);

        // Get configured attribute names (or null if not set)
        $attrUsername = $config->getField(ConfigEntity::SAML_ATTR_USERNAME);
        $attrEmail = $config->getField(ConfigEntity::SAML_ATTR_EMAIL);
        $attrFirstname = $config->getField(ConfigEntity::SAML_ATTR_FIRSTNAME);
        $attrLastname = $config->getField(ConfigEntity::SAML_ATTR_LASTNAME);
        $attrRealname = $config->getField(ConfigEntity::SAML_ATTR_REALNAME);

        // Fetch attributes from response
        $claims = $response->getAttributes();
        $user = [];

        // 1. Username (NameID)
        // Check if a custom attribute is configured for username
        if (!empty($attrUsername) && isset($claims[$attrUsername][0])) {
            $user[User::NAME] = $claims[$attrUsername][0];
        } else {
            // Default to NameID from Subject
            $user[User::NAME] = $response->getNameId();
        }

        if (empty($user[User::NAME])) {
            LoginFlow::printError(
                __('NameId attribute is missing in samlResponse', PLUGIN_NAME),
                'getUserInputFieldsFromSamlClaim',
                var_export($response, true)
            );
        }

        // Hostile guest account check
        if (strstr($user[User::NAME], '#EXT#@')) {
            LoginFlow::printError(
                __('Detected a default guest user in samlResponse, this is not supported<br>
                                      by glpiSAML. Please create a dedicated account for this user owned by your
                                      tenant/identity provider.<br>
                                      Also see: https://learn.microsoft.com/en-us/azure/active-directory/develop/saml-claims-customization', PLUGIN_NAME),
                'getUserInputFieldsFromSamlClaim',
                var_export($response, true)
            );
        }

        // 2. Email
        $emailFound = false;
        if (!empty($attrEmail) && isset($claims[$attrEmail][0])) {
            if (filter_var($claims[$attrEmail][0], FILTER_VALIDATE_EMAIL)) {
                $user[User::EMAIL] = [$claims[$attrEmail][0]];
                $emailFound = true;
            }
        }

        if (!$emailFound) {
            // Fallback to default schema
            if (isset($claims[User::SCHEMA_EMAILADDRESS][0]) && filter_var($claims[User::SCHEMA_EMAILADDRESS][0], FILTER_VALIDATE_EMAIL)) {
                $user[User::EMAIL] = [$claims[User::SCHEMA_EMAILADDRESS][0]];
                $emailFound = true;
            }
        }

        if (!$emailFound) {
            LoginFlow::printError(
                __('SamlResponse should have at least 1 valid email address for GLPI  to find
                                      the corresponding GLPI user or create it (with JIT enabled). For this purpose make
                                      sure either the IDP provided NameId property is populated with the email address format,
                                      or configure the proper attribute mapping in the configuration.', PLUGIN_NAME),
                'getUserInputFieldsFromSamlClaim',
                var_export($response, true)
            );
        }

        // 3. Firstname
        if (!empty($attrFirstname) && isset($claims[$attrFirstname][0])) {
            $user[User::FIRSTNAME] = $claims[$attrFirstname][0];
        } elseif (isset($claims[User::SCHEMA_FIRSTNAME][0])) {
            $user[User::FIRSTNAME] = $claims[User::SCHEMA_FIRSTNAME][0];
        } elseif (isset($claims[User::SCHEMA_GIVENNAME][0])) {
            $user[User::FIRSTNAME] = $claims[User::SCHEMA_GIVENNAME][0];
        }

        // Validate length
        if (isset($user[User::FIRSTNAME]) && strlen($user[User::FIRSTNAME]) > 255) {
            LoginFlow::printError(__('Provided firstname exceeded 255 characters.', 'getUserInputFieldsFromSamlClaim'));
        }

        // 4. Lastname (Realname in GLPI usually refers to Surname)
        if (!empty($attrLastname) && isset($claims[$attrLastname][0])) {
            $user[User::REALNAME] = $claims[$attrLastname][0];
        } elseif (isset($claims[User::SCHEMA_SURNAME][0])) {
            $user[User::REALNAME] = $claims[User::SCHEMA_SURNAME][0];
        }

        if (isset($user[User::REALNAME]) && strlen($user[User::REALNAME]) > 255) {
            LoginFlow::printError(__('Provided surname exceeded 255 characters.', 'getUserInputFieldsFromSamlClaim'));
        }

        // 5. Realname (Full name, if mapped differently or used as fallback)
        // GLPI 'realname' is usually surname, 'firstname' is firstname. 
        // If there's a specific 'realname' mapping, it might override surname or be used for something else?
        // In GLPI User object: realname = surname.
        // If the user configured 'saml_attr_realname', we treat it as surname override if saml_attr_lastname is not set or empty?
        // Or strictly as Realname (Surname). Let's assume ConfigEntity::SAML_ATTR_REALNAME maps to User::REALNAME (which is surname).
        // If both lastname and realname are configured, realname takes precedence in this logic if we put it last.
        if (!empty($attrRealname) && isset($claims[$attrRealname][0])) {
            $user[User::REALNAME] = $claims[$attrRealname][0];
        }

        // ... Keep logic for other fields (Mobile, Phone, JobTitle, Country, etc.) as is or add mappings for them too if requested. 
        // For now, only the requested fields were added to DB.

        // Groups
        $user[User::SAMLGROUPS] = isset($claims[User::SCHEMA_GROUPS]) ? $claims[User::SCHEMA_GROUPS] : [];

        // Other standard schemas (keep existing fallback logic)
        // jobTitle
        if (isset($claims[User::SCHEMA_JOBTITLE][0])) {
            $user[User::SAMLJOBTITLE] = $claims[User::SCHEMA_JOBTITLE][0];
        }
        // Mobile
        if (isset($claims[User::SCHEMA_MOBILE][0])) {
            $user[User::MOBILE] = $claims[User::SCHEMA_MOBILE][0];
        }
        // Phone
        if (isset($claims[User::SCHEMA_PHONE][0])) {
            $user[User::PHONE] = $claims[User::SCHEMA_PHONE][0];
        }
        // Country
        if (isset($claims[User::SCHEMA_COUNTRY][0])) {
            $user[User::SAMLCOUNTRY] = $claims[User::SCHEMA_COUNTRY][0];
        }
        // City
        if (isset($claims[User::SCHEMA_CITY][0])) {
            $user[User::SAMLCITY] = $claims[User::SCHEMA_CITY][0];
        }
        // Street
        if (isset($claims[User::SCHEMA_STREET][0])) {
            $user[User::SAMLSTREET] = $claims[User::SCHEMA_STREET][0];
        }

        // Set additional user fields for user creation (if needed)
        // These fields are used for user->add($input);
        $user[User::COMMENT] = __('Created by phpSaml Just-In-Time user creation on:' . date('Y-m-d H:i:s'));
        $password = bin2hex(random_bytes(20));
        $user[User::PASSWORD] = $password;
        $user[User::PASSWORDN] = $password;
        $user[User::AUTHTYPE] = 4;
        $user[User::SYNCDATE] = date('Y-m-d H:i:s');

        // Return the userArray.
        return $user;
    }
}
