/**
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2016 ForgeRock AS.
 */

define([
    "jquery",
    "lodash",
    "org/forgerock/commons/ui/common/util/Constants",
    "org/forgerock/commons/ui/common/main/Configuration"
], ($, _, constants, conf) => {
    let themePromise;

    return {
        loadThemeCSS (theme) {
            $("head").find("link[href*=favicon]").remove();

            $("<link/>", {
                rel: "icon",
                type: "image/x-icon",
                href: theme.path + theme.icon
            }).appendTo("head");

            $("<link/>", {
                rel: "shortcut icon",
                type: "image/x-icon",
                href: theme.path + theme.icon
            }).appendTo("head");

            _.forEach(theme.stylesheets, (stylesheet) => {
                $("<link/>", {
                    rel: "stylesheet",
                    type: "text/css",
                    href: stylesheet
                }).appendTo("head");
            });
        },

        loadThemeConfig () {
            const prom = $.Deferred();
            //check to see if the config file has been loaded already
            //if so use what is already there if not load it
            if (conf.globalData.themeConfig) {
                prom.resolve(conf.globalData.themeConfig);
                return prom;
            } else {
                return $.Deferred().resolve({
                    "path": "",
                    "icon": "favicon.ico",
                    "stylesheets": ["css/bootstrap.css", "css/structure.css", "css/theme.css"],
                    "settings": {
                        "logo": {
                            "src": "images/logo-horizontal.png",
                            "title": "Wren Security",
                            "alt": "Wren Security",
                            "height": "54px"
                        },
                        "loginLogo": {
                            "src": "images/login-logo.png",
                            "title": "Wren Security",
                            "alt": "Wren Security",
                            "width": "300px"
                        },
                        "footer": {
                            "mailto": "info@wrensecurity.org"
                        }
                    }
                });
            }
        },

        getTheme () {
            if (themePromise === undefined) {
                themePromise = this.loadThemeConfig().then((themeConfig) => {
                    conf.globalData.theme = themeConfig;
                    this.loadThemeCSS(themeConfig);
                    return themeConfig;
                });
            }
            return themePromise;
        }

    };
});
