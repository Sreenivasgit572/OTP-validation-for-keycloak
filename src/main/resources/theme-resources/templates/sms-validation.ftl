    <#import "template.ftl" as layout>
    <@layout.registrationLayout; section>
        <#if section = "title">
            ${msg("loginTitle",realm.name)}
        <#elseif section = "header">
            ${msg("loginTitleHtml",realm.name)}
        <#elseif section = "form">
            <form id="kc-totp-login-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
                <div class="${properties.kcFormGroupClass!}">
                    <div class="${properties.kcLabelWrapperClass!}">
                        <label for="totp" class="${properties.kcLabelClass!}">Enter SMS code</label>
                    </div>

                    <div class="${properties.kcInputWrapperClass!}">
                        <input id="totp" name="smsCode" type="text" class="${properties.kcInputClass!}" />
                    </div>
                </div>

                <div class="${properties.kcFormGroupClass!}">
                    <div id="kc-form-options" class="${properties.kcFormOptionsClass!}">
                        <div class="${properties.kcFormOptionsWrapperClass!}">
                        </div>
                    </div>

                    <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
                        <div class="${properties.kcFormButtonsWrapperClass!}">
                            <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonLargeClass!}" name="login" id="kc-login" type="submit" value="${msg("doLogIn")}"/>
                            <input class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}" onclick="window.location.href = '${client.baseUrl}'" name="cancel" id="kc-cancel" type="button" value="${msg("doCancel")}"/>
                            </div>
                    </div>
                </div>
            </form>
            <#if client?? && client.baseUrl?has_content>
                <p><a id="backToApplication" href="${client.baseUrl}">${msg("backToApplication")}</a></p>
            </#if>
        </#if>
    </@layout.registrationLayout>