"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.version = exports.default = exports.AxiosClient = void 0;
var _httpClient = require("../http-client");
var version = exports.version = "12.3.0";
var AxiosClient = exports.AxiosClient = (0, _httpClient.create)({
  headers: {
    'X-Client-Name': 'js-soroban-client',
    'X-Client-Version': version
  }
});
var _default = exports.default = AxiosClient;