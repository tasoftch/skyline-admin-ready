<?php

namespace Skyline\Admin\Ready\Controller;


use Skyline\Admin\Tool\UserGroupTool;
use Skyline\Admin\Tool\UserRoleTool;
use Skyline\CMS\Security\Authentication\AuthenticationServiceFactory;
use Skyline\CMS\Security\Tool\PasswordResetTool;
use Skyline\Admin\Tool\UserTool;
use Skyline\CMS\Security\UserSystem\Group;
use Skyline\CMS\Security\UserSystem\Role;
use Skyline\CMS\Security\UserSystem\User;
use Skyline\HTML\Bootstrap\Breadcrumb;
use Skyline\Router\Description\RegexActionDescription;
use Skyline\Security\Exception\SecurityException;
use Skyline\Security\Identity\IdentityInterface;
use Skyline\Security\Role\RoleInterface;
use Skyline\Translation\TranslationManager;
use Symfony\Component\Console\Exception\RuntimeException;
use TASoft\Service\ServiceManager;
use TASoft\Util\PDO;

/**
 * Class UserSystemActionController
 * @package Skyline\Admin\Ready\Controller
 * @role SKYLINE.ADMIN
 */
class UserSystemActionController extends AbstractGeneralAdminController
{
	/**
	 * @route literal /users
	 * @menu path /admin/User System/Users
	 * @menu action /admin/users
	 * @menu select %^/?admin/users%i
	 * @role SKYLINE.USERS.EDIT.VIEW
	 */
	public function listAllUsersAction() {
		/** @var TranslationManager $tm */
		$tm = $this->get(TranslationManager::SERVICE_NAME);
		$sm = ServiceManager::generalServiceManager();

		$enabledProviders = $sm->getParameter("security.user-providers.enabled");
		if(in_array(AuthenticationServiceFactory::USER_PROVIDER_DATABASE_NAME, $enabledProviders)) {
			/** @var PDO $PDO */
			$PDO = $this->PDO;

			$USERS = $PDO->select("SELECT * FROM SKY_USER ORDER BY (case when prename is NULL then username else prename end)");
		} else {
			$USERS = 0;
		}

		/** @var UserTool $uTool */
		$uTool = $this->get(UserTool::SERVICE_NAME);

		$this->renderModel([
			'BREAD' => (new Breadcrumb())
				->addItem('/admin/users', $tm->translateGlobal("User System"))
				->addItem('', $tm->translateGlobal("Users")),
			'USERS' => $USERS,
			'ME' => $this->getUser()->getUsername(),
			"CAN" => [
				"EDIT" => $uTool->hasRole('SKYLINE.USERS.EDIT.MODIFY'),
				'DELETE' => $uTool->hasRole('SKYLINE.USERS.DELETE'),
				"ADD" => $uTool->hasRoles('SKYLINE.USERS.EDIT.MODIFY && (SKYLINE.USERS.EDIT.ASSIGN || SKYLINE.USERS.EDIT.PRIVILEGE)')
			]
		]);
		$this->renderTemplate("admin-main", [
			"Content" => 'users'
		]);
	}

	/**
	 * @route regex %^/?users/add/(.+)%i
	 */
	public function addUserAction(RegexActionDescription $actionDescription) {
		$name = trim( urldecode( $actionDescription->getCaptures()[1] ) );

		/** @var UserTool $uTool */
		$uTool = $this->get(UserTool::SERVICE_NAME);

		if($u = $uTool->createUser($name, md5(microtime()))) {
			$this->stopAction(function() use ($u) {
				header("Location: /admin/users/edit/" . $u->getId());
			});
		}
	}

	/**
	 * @route regex %^/?users/edit/(\d+)%i
	 * @role SKYLINE.USERS.EDIT.MODIFY
	 */
	public function editUserAction(RegexActionDescription $actionDescription) {
		/** @var TranslationManager $tm */
		$tm = $this->get(TranslationManager::SERVICE_NAME);
		/** @var UserTool $uTool */
		$uTool = $this->get(UserTool::SERVICE_NAME);

		$CAN = [
			"ASSIGN" => $uTool->hasRole('SKYLINE.USERS.EDIT.ASSIGN'),
			'PRIVILEGE' => $uTool->hasRole('SKYLINE.USERS.EDIT.PRIVILEGE'),
			"DELETE" => $uTool->hasRole("SKYLINE.USERS.DELETE"),
			"PW_RESET" => $uTool->hasRole("SKYLINE.USERS.PW_RESET")
		];

		$sm = ServiceManager::generalServiceManager();
		$enabledProviders = $sm->getParameter("security.user-providers.enabled");

		$PROBLEM = 0;

		if(in_array(AuthenticationServiceFactory::USER_PROVIDER_DATABASE_NAME, $enabledProviders)) {
			/** @var PDO $PDO */
			$PDO = $this->PDO;
			$UID = $actionDescription->getCaptures()[1];

			if($uTool->getUserID() == $UID) {
				throw new SecurityException($tm->translateGlobal("You can not modify your own account with admin privileges."));
			}

			if(count($_POST)) {
				$options = $PDO->selectFieldValue("SELECT options FROM SKY_USER WHERE id = ?", 'options', [$UID]);
				if($options & User::OPTION_INTERNAL)
					throw new SecurityException($tm->translateGlobal("User is internal and can not be changed."));
			}

			if(isset($_POST["apply-information"])) {
				$this->verifyCSRF();
				try {
					$PDO->inject("UPDATE SKY_USER SET username = ?, prename = ?, surname = ?, email = ? WHERE id = $UID")->send([
						$_POST["the-username"],
						$_POST["the-prename"],
						$_POST["the-surname"],
						$_POST["the-email"],
					]);
					$PROBLEM = -1;
				} catch (\PDOException $exception) {
					if(stripos($exception->getMessage(), 'username') !== false) {
						$PROBLEM = $tm->translateGlobal("The desired username is already in use.");
					}
					elseif(stripos($exception->getMessage(), 'email') !== false) {
						$PROBLEM = $tm->translateGlobal("The desired email address is already in use.");
					}
				}
			}

			if(isset($_POST["apply-password"]) && $CAN["PW_RESET"]) {
				$this->verifyCSRF();

				$pw = $_POST["the-password"];

				if(!isset($_POST["ignore-conds"])) {
					$pl = AdministrationActionController::checkPW($sm->getParameter("security.password.reset.conditions") * 1, $pw, $sm);
					if($pl != 0) {
						switch ($pl) {
							case 1: $PROBLEM = $tm->translateGlobal("Password must not be empty"); break;
							case 2: $PROBLEM =  $tm->translateGlobal("Passwort must contain at least %d characters.", NULL, $sm->getParameter("security.password.reset.min-length")); break;
							case 4: $PROBLEM =  $tm->translateGlobal("Passwort must contain at least one number 0-9."); break;
							case 8: $PROBLEM =  $tm->translateGlobal("Passwort must contain at least one uppercase character A-Z."); break;
							case 16: $PROBLEM =  $tm->translateGlobal("Passwort must contain at least one lowercase character a-z."); break;
							case 32: $PROBLEM =  $tm->translateGlobal("Passwort must contain at least one special character: +-*/?!$;:_%%&@(){}[]#="); break;
							case 64: $PROBLEM =  $tm->translateGlobal("Password must only contain characters: %s", NULL, $sm->getParameter("security.password.reset.must-contain")); break;
							case 128: $PROBLEM =  $tm->translateGlobal("Password must not contain characters: %s", NULL, $sm->getParameter("security.password.reset.must-not-contain")); break;
						}
					}
				}

				if(!$PROBLEM) {
					$pwv = $_POST["the-passwordv"];
					if($pwv != $pw) {
						$PROBLEM = $tm->translateGlobal('Password verification does not match the password.');
					} else {
						/** @var PasswordResetTool $rTool */
						$rTool = $this->get(PasswordResetTool::SERVICE_NAME);

						$user = $uTool->getUser( $UID );
						if($rTool->updateUserPassword($user, $pw))
							$PROBLEM = -1;
						else
							$PROBLEM = $tm->translateGlobal("Could not update password.");
					}
				}
			}
			
			if(isset($_POST["apply-acl"])) {
				$this->verifyCSRF();

				$uTool->setCurrentUser( $uTool->getUser($UID) );

				if($CAN['ASSIGN']) {
					$uTool->assignGroups($_POST['groups'] ?? []);
				}

				if($CAN['PRIVILEGE']) {
					$uTool->assignRoles($_POST['roles'] ?? []);
				}

				$uTool->setCurrentUser();
			}

			$USER = $PDO->selectOne("SELECT * FROM SKY_USER WHERE id = ?", [$UID]);
			if(!$USER) {
				$this->stopAction(function() {
					header("Location: /admin/users");
				});
			}


			$GROUPS = $PDO->select("SELECT DISTINCT
id,
                name,
                description,
                case when groupid is not null then 1 else 0 end as selected
FROM SKY_GROUP
LEFT JOIN SKY_USER_GROUP ON groupid = id AND user = ?
ORDER BY name", [$USER['id']]);

			/** @var UserRoleTool $rTool */
			$rTool = $this->get(UserRoleTool::SERVICE_NAME);

			$ROLES = array_filter($rTool->getRoles(), function(Role $role) {
				$opt = Role::OPTION_ASSIGNABLE | Role::OPTION_VISIBLE;
				return ($role->getOptions() & $opt) == $opt;
			});

			$S_ROLES = array_map(function($v) {
				return $v["role"];
			} ,iterator_to_array($PDO->select("SELECT role FROM SKY_USER_ROLE WHERE user = ?", [$USER['id']])));

		} else {
			$USER = 0;
			$GROUPS = 0;
			$ROLES = 0;
			$S_ROLES = 0;
		}

		$this->renderModel([
			'CSRF' => $this->makeCSRFToken(),
			'BREAD' => (new Breadcrumb())
				->addItem('/admin/users', $tm->translateGlobal("User System"))
			->addItem('', $tm->translateGlobal("Edit User")),
			'USER' => $USER,
			"CAN" => $CAN,
			"GROUPS" => $GROUPS,
			"ROLES" => $ROLES,
			"S_ROLES" => $S_ROLES,
			'PROBLEM' => $PROBLEM
		]);
		$this->renderTemplate("admin-main", [
			"Content" => 'user-edit'
		]);
	}


	/**
	 * @route regex %^/?users/delete/(\d+)%i
	 * @role SKYLINE.USERS.DELETE
	 */
	public function deleteUserAction(RegexActionDescription $actionDescription) {
		/** @var TranslationManager $tm */
		$tm = $this->get(TranslationManager::SERVICE_NAME);
		/** @var UserTool $uTool */
		$uTool = $this->get(UserTool::SERVICE_NAME);

		$CAN = [
			"ASSIGN" => $uTool->hasRole('SKYLINE.USERS.EDIT.ASSIGN'),
			'PRIVILEGE' => $uTool->hasRole('SKYLINE.USERS.EDIT.PRIVILEGE'),
			"DELETE" => $uTool->hasRole("SKYLINE.USERS.DELETE"),
			"PW_RESET" => $uTool->hasRole("SKYLINE.USERS.PW_RESET")
		];

		$sm = ServiceManager::generalServiceManager();
		$enabledProviders = $sm->getParameter("security.user-providers.enabled");

		$PROBLEM = 0;

		if(in_array(AuthenticationServiceFactory::USER_PROVIDER_DATABASE_NAME, $enabledProviders)) {
			$USER = $uTool->getUser( $UID = $actionDescription->getCaptures()[1] );
			if(!$USER) {
				$this->stopAction(function() {
					header("Location: /admin/users");
				});
			}

			if($uTool->getUserID() == $UID) {
				throw new SecurityException($tm->translateGlobal("You can not delete your own account with admin privileges."));
			}

			if(method_exists($USER, 'getOptions') && $USER->getOptions() & User::OPTION_INTERNAL)
				throw new SecurityException($tm->translateGlobal("User is internal and can not be changed."));

			if(isset($_POST["delete-now"])) {
				$this->verifyCSRF();

				if($this->getIdentity()->getReliability() >= IdentityInterface::RELIABILITY_HTML_FORM) {
					$uTool->removeUser($USER);
					$this->stopAction(function() {
						header("Location: /admin/users");
					});
				}
			}
		} else {
			$USER = 0;
		}

		$this->renderModel([
			'CSRF' => $this->makeCSRFToken(),
			'BREAD' => (new Breadcrumb())
				->addItem('/admin/users', $tm->translateGlobal("User System"))
				->addItem('', $tm->translateGlobal("Delete User")),
			'USER' => $USER,
			'PROBLEM' => $PROBLEM,
			"USERNAME" => $uTool->getUserName()
		]);
		$this->renderTemplate("admin-main", [
			"Content" => 'user-delete'
		]);
	}


	/**
	 * @route literal /groups
	 * @menu path /admin/User System/Groups
	 * @menu action /admin/groups
	 * @menu select %^/?admin/groups%i
	 * @role SKYLINE.GROUPS.EDIT.VIEW
	 */
	public function listAllGroupsAction() {
		/** @var TranslationManager $tm */
		$tm = $this->get(TranslationManager::SERVICE_NAME);

		$sm = ServiceManager::generalServiceManager();
		$enabledProviders = $sm->getParameter("security.user-providers.enabled");

		/** @var UserTool $uTool */
		$uTool = $this->get(UserTool::SERVICE_NAME);

		$PROBLEM = 0;
		$CAN = [
			"EDIT" => $uTool->hasRole('SKYLINE.GROUPS.EDIT.MODIFY'),
			'ADD' => $uTool->hasRoles('SKYLINE.GROUPS.EDIT.PRIVILEGE && SKYLINE.GROUPS.EDIT.MODIFY'),
			"DELETE" => $uTool->hasRole("SKYLINE.GROUPS.DELETE")
		];

		if(in_array(AuthenticationServiceFactory::USER_PROVIDER_DATABASE_NAME, $enabledProviders)) {
			/** @var PDO $PDO */
			$PDO = $this->PDO;

			$GROUPS = $PDO->select("SELECT id, name, description, count(user) AS members, options FROM SKY_GROUP LEFT JOIN SKY_USER_GROUP ON groupid = id GROUP BY name ORDER BY name");
		} else {
			$GROUPS = 0;
		}

		$this->renderModel([
			'BREAD' => (new Breadcrumb())
				->addItem('/admin/users', $tm->translateGlobal("User System"))
				->addItem('', $tm->translateGlobal("Groups")),
			'GROUPS' => $GROUPS,
			"CAN" => $CAN
		]);
		$this->renderTemplate("admin-main", [
			"Content" => 'groups'
		]);
	}


	/**
	 * @route regex %^/?groups/add/(.+)%i
	 * @role SKYLINE.GROUPS.EDIT.MODIFY
	 * @role SKYLINE.GROUPS.EDIT.PRIVILEGE
	 */
	public function addGroupAction(RegexActionDescription $actionDescription) {
		$name = trim( urldecode( $actionDescription->getCaptures()[1] ) );

		/** @var UserGroupTool $gToo */
		$gToo = $this->get(UserGroupTool::SERVICE_NAME);

		if($g = $gToo->addGroup($name)) {
			$this->stopAction(function() use ($g) {
				header("Location: /admin/groups/edit/" . $g->getId());
			});
		}
	}

	/**
	 * @route regex %^/?groups/edit/(\d+)%i
	 * @role SKYLINE.GROUPS.EDIT.MODIFY
	 */
	public function editGroupAction(RegexActionDescription $actionDescription) {
		/** @var UserGroupTool $gTool */
		$gTool = $this->get(UserGroupTool::SERVICE_NAME);
		/** @var PDO $PDO */
		$PDO = $this->PDO;

		/** @var TranslationManager $tm */
		$tm = $this->get(TranslationManager::SERVICE_NAME);

		$GID = $actionDescription->getCaptures()[1] * 1;
		$PROBLEM = 0;

		$GROUP = $gTool->getGroup( $actionDescription->getCaptures()[1] );
		if(!$GROUP) {
			$this->stopAction(function() {
				header("Location: /admin/groups");
			});
		}

		if(isset($_POST["apply-information"])) {
			$this->verifyCSRF();

			if($GROUP->isInternal()) {
				throw new \Exception($tm->translateGlobal("This group is internal and can not be modified.", 403));
			}


			$PROBLEM = -1;

			try {
				if(!$_POST["gname"])
					throw new \RuntimeException();
				$gTool->updateGroup($GROUP, $_POST["gname"] != $GROUP->getName() ? $_POST["gname"] : NULL, $_POST["gdesc"]);
			} catch (\PDOException $exception) {
				$PROBLEM = $tm->translateGlobal("Desired name is already in use.");
			} catch (\RuntimeException $exception) {
				$PROBLEM = $tm->translateGlobal("Name must not be empty.");
			}
		}

		if(isset($_POST["apply-acl"])) {
			$this->verifyCSRF();

			$gTool->assignRoles($GROUP, $_POST["roles"] ?? []);
		}

		/** @var UserTool $uTool */
		$uTool = $this->get(UserTool::SERVICE_NAME);

		/** @var UserRoleTool $rTool */
		$rTool = $this->get(UserRoleTool::SERVICE_NAME);

		$ROLES = array_filter($rTool->getRoles(), function(Role $role) {
			$opt = Role::OPTION_ASSIGNABLE | Role::OPTION_VISIBLE;
			return ($role->getOptions() & $opt) == $opt;
		});

		$S_ROLES = array_map(function($v) {
			return $v["role"];
		} ,iterator_to_array($PDO->select("SELECT role FROM SKY_GROUP_ROLE WHERE groupid = ?", [ $GROUP->getId() ])));


		$CAN = [
			'PRIVILEGE' => $uTool->hasRole("SKYLINE.GROUPS.EDIT.PRIVILEGE")
		];

		$this->renderModel([
			'CSRF' => $this->makeCSRFToken(),
			'BREAD' => (new Breadcrumb())
				->addItem('/admin/users', $tm->translateGlobal("User System"))
				->addItem('/admin/groups', $tm->translateGlobal("Groups"))
				->addItem('', $tm->translateGlobal("Edit Group")),

			'GROUP' => $GROUP,
			"ROLES" => $ROLES,
			'S_ROLES' => $S_ROLES,
			"CAN" => $CAN,
			"PROBLEM" => $PROBLEM
		]);
		$this->renderTemplate("admin-main", [
			"Content" => 'group-edit'
		]);
	}

	/**
	 * @route regex %^/?groups/delete/(\d+)%i
	 * @role SKYLINE.GROUPS.DELETE
	 */
	public function deleteGroupAction(RegexActionDescription $actionDescription) {
		/** @var TranslationManager $tm */
		$tm = $this->get(TranslationManager::SERVICE_NAME);
		/** @var UserGroupTool $gTool */
		$gTool = $this->get(UserGroupTool::SERVICE_NAME);

		/** @var UserTool $uTool */
		$uTool = $this->get(UserTool::SERVICE_NAME);


		$GROUP = $gTool->getGroup( $actionDescription->getCaptures()[1] );
		if(!$GROUP) {
			$this->stopAction(function() {
				header("Location: /admin/groups");
			});
		}

		if($GROUP->isInternal()) {
			throw new \Exception($tm->translateGlobal("This group is internal and can not be modified.", 403));
		}

		if(isset($_POST["delete-now"])) {
			$this->verifyCSRF();

			if($this->getIdentity()->getReliability() >= IdentityInterface::RELIABILITY_HTML_FORM) {
				$gTool->removeGroup($GROUP);
				$this->stopAction(function() {
					header("Location: /admin/groups");
				});
			}
		}

		$this->renderModel([
			'CSRF' => $this->makeCSRFToken(),
			'BREAD' => (new Breadcrumb())
				->addItem('/admin/users', $tm->translateGlobal("User System"))
				->addItem('/admin/groups', $tm->translateGlobal("Groups"))
				->addItem('', $tm->translateGlobal("Delete Group")),
			'GROUP' => $GROUP,
			"USERNAME" => $uTool->getUserName()
		]);
		$this->renderTemplate("admin-main", [
			"Content" => 'group-delete'
		]);
	}


	/**
	 * @route literal /roles
	 * @menu path /admin/User System/Roles
	 * @menu action /admin/roles
	 * @menu select %^/?admin/roles%
	 * @role SKYLINE.ROLES.EDIT.VIEW
	 */
	public function listAllRolesAction() {
		/** @var UserTool $uTool */
		$uTool = $this->get(UserTool::SERVICE_NAME);
		/** @var TranslationManager $tm */
		$tm = $this->get(TranslationManager::SERVICE_NAME);

		$CAN = [
			'EDIT' => $uTool->hasRole("SKYLINE.ROLES.EDIT"),
			'DELETE' => $uTool->hasRole("SKYLINE.ROLES.DELETE")
		];

		/** @var UserRoleTool $rTool */
		$rTool = $this->get(UserRoleTool::SERVICE_NAME);
		$ROLES = $rTool->getRoles();

		$this->renderModel([
			'BREAD' => (new Breadcrumb())
				->addItem('/admin/users', $tm->translateGlobal("User System"))
				->addItem('', $tm->translateGlobal("Roles")),
			'ROLES' => $ROLES,
			"CAN" => $CAN
		]);
		$this->renderTemplate("admin-main", [
			"Content" => 'roles'
		]);
	}

	/**
	 * @route regex %^/?roles/add/(.+)%i
	 * @role SKYLINE.ROLES.EDIT
	 */
	public function addRoleAction(RegexActionDescription $actionDescription) {
		$name = trim( urldecode( $actionDescription->getCaptures()[1] ) );
		$parent = ($_GET["parent"] ?? 0) * 1;


		/** @var UserRoleTool $rTool */
		$rTool = $this->get(UserRoleTool::SERVICE_NAME);
		if($parent) {
			$parent = $rTool->getRole($parent);
		} else
			$parent = NULL;

		if($r = $rTool->addRole($name, $parent, NULL, Role::OPTION_VISIBLE)) {
			$this->stopAction(function() use ($r) {
				header("Location: /admin/roles/edit/" . $r->getId());
			});
		}
	}

	/**
	 * @route regex %^/?roles/edit/(\d+)%
	 * @role SKYLINE.ROLES.EDIT
	 */
	public function editRoleAction(RegexActionDescription $actionDescription) {
		/** @var UserRoleTool $rTool */
		$rTool = $this->get(UserRoleTool::SERVICE_NAME);

		/** @var TranslationManager $tm */
		$tm = $this->get(TranslationManager::SERVICE_NAME);

		$RID = $actionDescription->getCaptures()[1] * 1;
		$PROBLEM = 0;

		$ROLE = $rTool->getRole( $RID );
		if(!$ROLE) {
			$this->stopAction(function() {
				header("Location: /admin/roles");
			});
		}

		if(isset($_POST["apply-information"])) {
			$this->verifyCSRF();
			$options = 0;
			foreach (($_POST['options'] ?? []) as $opt)
				$options |= $opt;

			$PROBLEM = -1;

			try {
				if(!preg_match("/^[a-z0-9_]+$/i", $_POST['rname']))
					throw new \RuntimeException();
				$r = explode(".", $ROLE->getRole());
				$rname = array_pop($r);
				$rTool->updateRole($ROLE, $_POST["rname"] != $rname ? $_POST['rname'] : NULL, $_POST["rdesc"], $options);

				$parent = $rTool->getParent($ROLE);
				$rpar = ($r = $_POST["rparent"] * 1) ? $rTool->getRole($r) : NULL;

				if($parent && $rpar) {
					// Parent exists, maybe modified parent sent
					if($parent->getId() != $rpar->getId())
						$rTool->updateRoleParent($ROLE, $rpar);
				} elseif($parent) {
					if(!$rpar)
						$rTool->updateRoleParent($ROLE, NULL);
				} elseif($rpar) {
					$rTool->updateRoleParent($ROLE, $rpar);
				}
			} catch (\PDOException $exception) {
				$PROBLEM = $tm->translateGlobal("Desired name is already in use.");
			} catch (SecurityException $exception) {
				$PROBLEM = $tm->translateGlobal("Role name already exists.");
			} catch (\RuntimeException $exception) {
				$PROBLEM = $tm->translateGlobal("Name must not be empty and contain only latin characters, numbers and underscore.");
			}
		}



		if($ROLE->isInternal()) {
			throw new \Exception($tm->translateGlobal("This role is internal and can not be modified.", 403));
		}


		/** @var UserTool $uTool */
		$uTool = $this->get(UserTool::SERVICE_NAME);

		$ROLES = array_filter($rTool->getRoles(), function(Role $role) {
			if($role->getOptions() & Role::OPTION_FINAL)
				return false;
			if($role->getId() == -1 || $role->getRole() == Role::ROLE_ROOT)
				return false;
			return true;
		});

		$this->renderModel([
			'CSRF' => $this->makeCSRFToken(),
			'BREAD' => (new Breadcrumb())
				->addItem('/admin/users', $tm->translateGlobal("User System"))
				->addItem('/admin/roles', $tm->translateGlobal("Roles"))
				->addItem('', $tm->translateGlobal("Edit Role")),

			'ROLE' => $ROLE,
			"ROLES" => $ROLES,
			"PROBLEM" => $PROBLEM
		]);
		$this->renderTemplate("admin-main", [
			"Content" => 'role-edit'
		]);
	}

	/**
	 * @route regex %^/?roles/delete/(\d+)%i
	 * @role SKYLINE.ROLES.DELETE
	 */
	public function deleteRoleAction(RegexActionDescription $actionDescription) {
		/** @var TranslationManager $tm */
		$tm = $this->get(TranslationManager::SERVICE_NAME);

		/** @var UserTool $uTool */
		$uTool = $this->get(UserTool::SERVICE_NAME);

		/** @var UserRoleTool $rTool */
		$rTool = $this->get(UserRoleTool::SERVICE_NAME);

		$ROLE = $rTool->getRole( $actionDescription->getCaptures()[1] );
		if(!$ROLE) {
			$this->stopAction(function() {
				header("Location: /admin/roles");
			});
		}

		if($ROLE->isInternal()) {
			throw new \Exception($tm->translateGlobal("This role is internal and can not be modified.", 403));
		}

		if(isset($_POST["delete-now"])) {
			$this->verifyCSRF();

			if($this->getIdentity()->getReliability() >= IdentityInterface::RELIABILITY_HTML_FORM) {
				$rTool->removeRole($ROLE);
				$this->stopAction(function() {
					header("Location: /admin/roles");
				});
			}
		}

		$this->renderModel([
			'CSRF' => $this->makeCSRFToken(),
			'BREAD' => (new Breadcrumb())
				->addItem('/admin/users', $tm->translateGlobal("User System"))
				->addItem('/admin/groups', $tm->translateGlobal("Groups"))
				->addItem('', $tm->translateGlobal("Delete Group")),
			'ROLE' => $ROLE,
			"USERNAME" => $uTool->getUserName()
		]);
		$this->renderTemplate("admin-main", [
			"Content" => 'role-delete'
		]);
	}
}