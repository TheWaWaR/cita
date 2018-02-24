pragma solidity ^0.4.18;

import "./permission.sol";


/// @title Authorization about the permission and account
/// @notice Only be called by permission_management contract except query interface 
///         TODO Set multi auth interface
contract Authorization {

    address permissionManagementAddr = 0x00000000000000000000000000000000013241b2;
    address newPermissionAddr = 0x00000000000000000000000000000000013241b5;
    address deletePermissionAddr = 0x00000000000000000000000000000000023241b5;
    address updatePermissionAddr = 0x00000000000000000000000000000000033241B5;
    address setAuthAddr = 0x00000000000000000000000000000000043241b5;
    address cancelAuthAddr = 0x00000000000000000000000000000000055241B5;

    mapping(address => address[]) permissions;
    mapping(address => address[]) accounts;

    event AuthSetted(address indexed _account, address indexed _permission);
    event AuthCanceled(address indexed _account, address indexed _permission);
    event AuthCleared(address indexed _account);

    modifier onlyPermissionManagement {
        require(permissionManagementAddr == msg.sender);
        _;
    }

    /// @dev Initialize the superAdmin's auth
    function Authorization(address _superAdmin) public {
        // TODO
        _setAuth(_superAdmin, newPermissionAddr);
        _setAuth(_superAdmin, deletePermissionAddr);
        _setAuth(_superAdmin, updatePermissionAddr);
        _setAuth(_superAdmin, setAuthAddr);
        _setAuth(_superAdmin, cancelAuthAddr);
    }

    /// @dev Set authorization
    function setAuth(address _account, address _permission)
        public 
        onlyPermissionManagement
        returns (bool)
    {
        return _setAuth(_account, _permission);
    }

    /// @dev Cancel authorization
    function cancelAuth(address _account, address _permission)
        public 
        onlyPermissionManagement
        returns (bool)
    {
        addressDelete(_account, accounts[_permission]);
        addressDelete(_permission, permissions[_account]);
        AuthCanceled(_account, _permission);
        return true;
    }

    /// @dev Clear the account's permissions
    function clearAuth(address _account)
        public 
        onlyPermissionManagement
        returns (bool)
    {
        // Delete the account of all the account's permissions
        for (uint i = 0; i < permissions[_account].length; i++)
            addressDelete(_account, accounts[permissions[_account][i]]);

        delete permissions[_account];

        AuthCleared(_account);
        return true;
    }

    /// @dev Query the account's permissions
    function queryPermissions(address _account)
        public
        view
        returns (address[] _permissions)
    {
        return permissions[_account];
    }

    /// @dev Query the permission's accounts
    function queryAccounts(address _permission)
        public
        view
        returns (address[] _accounts)
    {
        return accounts[_permission];
    }

    /// @dev Check Permission
    function checkPermission(address _account, address _cont, bytes4 _func)
        public
        view
        returns (bool)
    {
        address[] memory perms = queryPermissions(_account);

        for (uint i = 0; i < perms.length; i++) {
            Permission perm = Permission(perms[i]);
            if (perm.inPermission(_cont, _func))
                return true;
        }

        return false;
    }

    /// @dev Delete the value of the address array
    function addressDelete(address _value, address[] storage _array)
        private 
        returns (bool)
    {
        var index = addressIndex(_value,  _array);
        // Not found
        if (index >= _array.length)
            return false;

        // Remove the gap
        for (uint i = index; i < _array.length-1; i++)
            _array[i] = _array[i+1];

        // Also delete the last element
        delete _array[_array.length-1];
        _array.length--;
        return true;
    }

    /// @dev Get the index of the value in the bytes32 array
    /// @return The index. If i == length, means not find
    function addressIndex(address _value, address[] _array)
        pure
        private 
        returns (uint i)
    {
        // Find the index of the value in the array
        for (i = 0; i < _array.length; i++) {
            if (_value == _array[i])
                return i;
        }
    }
    /// @dev Set authorization
    function _setAuth(address _account, address _permission)
        private 
        returns (bool)
    {
        permissions[_account].push(_permission);
        accounts[_permission].push(_account);
        AuthSetted(_account, _permission);
        return true;
    }
}
