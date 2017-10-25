import * as $ from "jquery";

class myJQ {
	static postJSON(url: string, data?: any): Promise<any> {
		data = data || {};
		return $.ajax({
			url: url,
			data: JSON.stringify(data),
			method: "POST",
			contentType: "application/json",
			dataType: "json"
		});
	}

	static putJSON(url: string, data?: any): Promise<any> {
		data = data || {};
		return $.ajax({
			url: url,
			data: JSON.stringify(data),
			method: "PUT",
			contentType: "application/json",
			dataType: "json"
		});
	}

	static getJSON(url: string, data?: any): Promise<any> {
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
	}

	static deleteJSON(url: string, data?: any): Promise<any> {
		return $.ajax({
			url: url,
			data: JSON.stringify(data),
			method: "DELETE",
			contentType: "application/json",
			dataType: "json"
		});
	}
}

export default class pzAPI {
	static base_url = window.location.protocol + "//" + window.location.host;

	static _copyObject(o): any {
		var newObj = {};
		for (var k in o) {
			newObj[k] = o[k];
		}
		return newObj;
	}

	static login = function (email, password) {
		const url = pzAPI.base_url + "/api/v1/login";
		const data = {
			email: email,
			password: password
		}
		return myJQ.postJSON(url, data);
	}

	static logout () {
		const url = pzAPI.base_url + "/api/v1/logout";
		return myJQ.postJSON(url);
	}

	static signup (email, password, confirm_password) {
		const url = pzAPI.base_url + "/api/v1/user/signup";
		const data = {
			email: email,
			password: password,
			confirm_password: confirm_password
		}
		return myJQ.postJSON(url, data);
	}

	static getCSRFToken () {
		const url = pzAPI.base_url + "/api/v1/csrf_token";
		return myJQ.getJSON(url);
	}

	static getEntries () {
		const url = pzAPI.base_url + "/api/v1/entries";
		return myJQ.getJSON(url);
	}

	static getEntriesV2() {
		const url = pzAPI.base_url + "/api/v2/entries";
		return myJQ.getJSON(url);
	}

	static _createEntry(entry: any, csrf_token: string): Promise<any> {
		const url = pzAPI.base_url + "/api/v1/entries/new";
		const data = pzAPI._copyObject(entry);
		data.csrf_token = csrf_token;
		return myJQ.postJSON(url, data);
	}

	static createEntry(entry: any): Promise<any> {
		return pzAPI.getCSRFToken()
			.then(function (response) {
				return pzAPI._createEntry(entry, response);
			});
	}

	static _editEntry(entry_id: number, entry: any, csrf_token: string) {
		const url = "/api/v1/entries/" + entry_id;
		const data = pzAPI._copyObject(entry);
		data.csrf_token = csrf_token;
		return myJQ.postJSON(url, data);
	}

	static editEntry(entry_id: number, entry: any) {
		return pzAPI.getCSRFToken()
			.then(function (response) {
				return pzAPI._editEntry(entry_id, entry, response);
			});
	}

	static _deleteEntry(csrf_token: string, entry_id: number) {
		const url = "/api/v1/entries/" + entry_id;
		return myJQ.deleteJSON(url, { "csrf_token": csrf_token });
	}

	static deleteEntry (entry_id) {
		return pzAPI.getCSRFToken()
			.then(function (response) {
				return pzAPI._deleteEntry(response, entry_id);
			});
	}

	static _recoverAccount (email, token) {
		const url = "/api/v1/user/recover";
		const data = { "csrf_token": token, "email": email };
		return myJQ.postJSON(url, data);
	}

	static recoverAccount (email) {
		return pzAPI.getCSRFToken()
			.then(function (response) {
				return pzAPI._recoverAccount(email, response);
			});
	}

	static _recoverAccountConfirm (csrfToken, token, password, confirmPassword) {
		const url = "/api/v1/user/recover/confirm";
		const data = {
			"token": token,
			"password": password,
			"confirm_password": confirmPassword
		}
		return myJQ.postJSON(url, data);
	}

	static recoverAccountConfirm (token, password, confirmPassword) {
		return pzAPI.getCSRFToken()
			.then(function (response) {
				return pzAPI._recoverAccountConfirm(response, token, password, confirmPassword);
			});
	}

	static _updateUserPassword (csrfToken, oldPassword, newPassword, confirmNewPassword) {
		const url = "/api/v1/user/password";
		const data = {
			"csrf_token": csrfToken,
			"old_password": oldPassword,
			"new_password": newPassword,
			"confirm_new_password": confirmNewPassword
		}
		return myJQ.putJSON(url, data);
	}

	static updateUserPassword(oldPassword: string, newPassword: string, confirmNewPassword: string) {
		return pzAPI.getCSRFToken()
			.then(function (response) {
				return pzAPI._updateUserPassword(response, oldPassword, newPassword, confirmNewPassword);
			});
	}

	static _updateUserPreferences(csrfToken: string, prefs: any) {
		if (Object.keys(prefs).length === 0) {
			throw "User preferences cannot be an empty object";
		}
		const url = "/api/v1/user/preferences";
		const data = pzAPI._copyObject(prefs);
		data.csrf_token = csrfToken;
		return myJQ.putJSON(url, data);
	}

	static updateUserPreferences (prefs) {
		if (Object.keys(prefs).length === 0) {
			throw "User preferences cannot be an empty object";
		}
		return pzAPI.getCSRFToken()
			.then(function (response) {
				return pzAPI._updateUserPreferences(response, prefs);
			});
	}

	static _deleteUser (csrfToken, password) {
		const url = "/api/v1/user";
		const data = { "password": password, "csrf_token": csrfToken };
		return myJQ.deleteJSON(url, data);
	}

	static deleteUser (password) {
		return pzAPI.getCSRFToken()
			.then(function (response) {
				return pzAPI._deleteUser(response, password);
			});
	}

	static getDocuments () {
		const url = pzAPI.base_url + "/api/v1/docs";
		return myJQ.getJSON(url);
	}

	/**
	 * This is a huge pain in the ass and can't take advantage of myJQ
	 */
	static _createDocument (csrfToken, name, file) {
		const url = pzAPI.base_url + "/api/v1/docs";
		const data = new FormData();
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
	}

	static createDocument (name, file) {
		return pzAPI.getCSRFToken().then(function(csrfToken) {
			return pzAPI._createDocument(csrfToken, name, file);
		});
	}

	static getDocument (id) {
		const url = pzAPI.base_url + "/api/v1/docs/" + id;
		return myJQ.getJSON(url);
	}

	static _editDocument (csrfToken, id, name, file) {
		const url = pzAPI.base_url + "/api/v1/docs/" + id;
		const data = new FormData();
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
	}

	static editDocument (id, name, file) {
		console.assert(typeof name === "string");
		return pzAPI.getCSRFToken().then(function(csrfToken) {
			return pzAPI._editDocument(csrfToken, id, name, file);
		});
	}
}
