import * as $ from "jquery";

var myJQ = (function () {
	function myJQ() {
	}

	myJQ.postJSON = function (url, data) {
		data = data || {};
		return $.ajax({
			url: url,
			data: JSON.stringify(data),
			method: "POST",
			contentType: "application/json",
			dataType: "json"
		});
	};

	myJQ.putJSON = function (url, data) {
		data = data || {};
		return $.ajax({
			url: url,
			data: JSON.stringify(data),
			method: "PUT",
			contentType: "application/json",
			dataType: "json"
		});
	};

	myJQ.getJSON = function (url, data) {
		data = data || {};
		if (Object.keys(data).length > 0) {
			url += "?" + $.param(data);
		}
		return $.ajax({
			url: url,
			method: "GET",
			contentType: "application/json",
			dataType: "json"
		});
	};

	myJQ.deleteJSON = function (url, data) {
		return $.ajax({
			url: url,
			data: JSON.stringify(data),
			method: "DELETE",
			contentType: "application/json",
			dataType: "json"
		});
	};
	return myJQ;
}());

//export default class pzAPI {
var pzAPI = (function () {
	function pzAPI() {
	}

	pzAPI._copyObject = function (o) {
		var newObj = {};
		for (var k in o) {
			newObj[k] = o[k];
		}
		return newObj;
	};

	pzAPI.login = function (email, password) {
		var url = pzAPI.base_url + "/api/v1/login";
		var data = {
			email: email,
			password: password
		};
		return myJQ.postJSON(url, data);
	};

	pzAPI.logout = function () {
		var url = pzAPI.base_url + "/api/v1/logout";
		return myJQ.postJSON(url);
	};

	pzAPI.signup = function (email, password, confirm_password) {
		var url = pzAPI.base_url + "/api/v1/user/signup";
		var data = {
			email: email,
			password: password,
			confirm_password: confirm_password
		};
		return myJQ.postJSON(url, data);
	};

	pzAPI.getCSRFToken = function () {
		var url = pzAPI.base_url + "/api/v1/csrf_token";
		return myJQ.getJSON(url);
	};

	pzAPI.getEntries = function () {
		var url = pzAPI.base_url + "/api/v1/entries";
		return myJQ.getJSON(url);
	};

	pzAPI.getEntriesV2 = function () {
		var url = pzAPI.base_url + "/api/v2/entries";
		return myJQ.getJSON(url);
	};

	pzAPI._createEntry = function (entry, csrf_token) {
		var url = pzAPI.base_url + "/api/v1/entries/new";
		var data = pzAPI._copyObject(entry);
		data.csrf_token = csrf_token;
		return myJQ.postJSON(url, data);
	};

	pzAPI.createEntry = function (entry) {
		return pzAPI.getCSRFToken()
			.then(function (response) {
				return pzAPI._createEntry(entry, response);
			});
	};

	pzAPI._editEntry = function (entry_id, entry, csrf_token) {
		var url = "/api/v1/entries/" + entry_id;
		var data = pzAPI._copyObject(entry);
		data.csrf_token = csrf_token;
		return myJQ.postJSON(url, data);
	};

	pzAPI.editEntry = function (entry_id, entry) {
		return pzAPI.getCSRFToken()
			.then(function (response) {
				return pzAPI._editEntry(entry_id, entry, response);
			});
	};

	pzAPI._deleteEntry = function (csrf_token, entry_id) {
		var url = "/api/v1/entries/" + entry_id;
		return myJQ.deleteJSON(url, { "csrf_token": csrf_token });
	};

	pzAPI.deleteEntry = function (entry_id) {
		return pzAPI.getCSRFToken()
			.then(function (response) {
				return pzAPI._deleteEntry(response, entry_id);
			});
	};

	pzAPI._recoverAccount = function (email, token) {
		var url = "/api/v1/user/recover";
		var data = { "csrf_token": token, "email": email };
		return myJQ.postJSON(url, data);
	};

	pzAPI.recoverAccount = function (email) {
		return pzAPI.getCSRFToken()
			.then(function (response) {
				return pzAPI._recoverAccount(email, response);
			});
	};

	pzAPI._recoverAccountConfirm = function (csrfToken, token, password, confirmPassword) {
		var url = "/api/v1/user/recover/confirm";
		var data = {
			"token": token,
			"password": password,
			"confirm_password": confirmPassword
		};
		return myJQ.postJSON(url, data);
	};

	pzAPI.recoverAccountConfirm = function (token, password, confirmPassword) {
		return pzAPI.getCSRFToken()
			.then(function (response) {
				return pzAPI._recoverAccountConfirm(response, token, password, confirmPassword);
			});
	};

	pzAPI._updateUserPassword = function (csrfToken, oldPassword, newPassword, confirmNewPassword) {
		var url = "/api/v1/user/password";
		var data = {
			"csrf_token": csrfToken,
			"old_password": oldPassword,
			"new_password": newPassword,
			"confirm_new_password": confirmNewPassword
		};
		return myJQ.putJSON(url, data);
	};

	pzAPI.updateUserPassword = function (oldPassword, newPassword, confirmNewPassword) {
		return pzAPI.getCSRFToken()
			.then(function (response) {
				return pzAPI._updateUserPassword(response, oldPassword, newPassword, confirmNewPassword);
			});
	};

	pzAPI._updateUserPreferences = function (csrfToken, prefs) {
		if (Object.keys(prefs).length === 0) {
			throw "User preferences cannot be an empty object";
		}
		var url = "/api/v1/user/preferences";
		var data = pzAPI._copyObject(prefs);
		data.csrf_token = csrfToken;
		return myJQ.putJSON(url, data);
	};

	pzAPI.updateUserPreferences = function (prefs) {
		if (Object.keys(prefs).length === 0) {
			throw "User preferences cannot be an empty object";
		}
		return pzAPI.getCSRFToken()
			.then(function (response) {
				return pzAPI._updateUserPreferences(response, prefs);
			});
	};

	pzAPI._deleteUser = function (csrfToken, password) {
		var url = "/api/v1/user";
		var data = { "password": password, "csrf_token": csrfToken };
		return myJQ.deleteJSON(url, data);
	};

	pzAPI.deleteUser = function (password) {
		return pzAPI.getCSRFToken()
			.then(function (response) {
				return pzAPI._deleteUser(response, password);
			});
	};

	pzAPI.getDocuments = function() {
		var url = pzAPI.base_url + "/api/v1/docs";
		return myJQ.getJSON(url);
	};

	/**
	 * This is a huge pain in the ass and can't take advantage of myJQ
	 */
	pzAPI._createDocument = function(csrfToken, name, file) {
		var url = pzAPI.base_url + "/api/v1/docs";
		var data = new FormData();
		data.append("csrf_token", csrfToken);
		data.append("name", name);
		data.append("document", file);
		return $.ajax({
			url: url,
			type: "POST",
			data: data,
			processData: false,
			contentType: false
			//contentType: "multipart/form-data"
		});
	};

	pzAPI.createDocument = function(name, file) {
		return pzAPI.getCSRFToken()
			.then(function(csrfToken) {
				return pzAPI._createDocument(csrfToken, name, file);
			});
	};

	pzAPI.getDocument = function(id) {
		var url = pzAPI.base_url + "/api/v1/docs/" + id;
		return myJQ.getJSON(url);
	};

	pzAPI._editDocument = function(csrfToken, id, name, file) {
		var url = pzAPI.base_url + "/api/v1/docs/" + id;
		var data = new FormData();
		data.append("csrf_token", csrfToken);
		data.append("name", name);
		data.append("document", file);
		return $.ajax({
			url: url,
			type: "POST",
			data: data,
			processData: false,
			contentType: false
			//contentType: "multipart/form-data"
		});
	};

	pzAPI.editDocument = function(id, name, file) {
		console.assert(typeof name === "string");
		return pzAPI.getCSRFToken()
			.then(function(csrfToken) {
				return pzAPI._editDocument(csrfToken, id, name, file);
			});
	};

	return pzAPI;
}());

pzAPI.base_url = window.location.protocol + "//" + window.location.host;

if (typeof module !== "undefined" && module.exports) {
	module.exports = pzAPI;
}
