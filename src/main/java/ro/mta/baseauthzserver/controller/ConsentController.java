package ro.mta.baseauthzserver.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Controller
public class ConsentController {

    RegisteredClientRepository registeredClientRepository;

    public ConsentController(RegisteredClientRepository registeredClientRepository) {
        this.registeredClientRepository = registeredClientRepository;
    }

    @GetMapping(value = "/oauth2/consent")
    public String consent(Principal principal, Model model,
                          HttpServletRequest request) {

        // Get all parameters from the original authorization request
        Map<String, String[]> parameterMap = request.getParameterMap();

        String clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID);
        String scope = request.getParameter(OAuth2ParameterNames.SCOPE);
        String state = request.getParameter(OAuth2ParameterNames.STATE);

        Set<String> scopesToApprove = new LinkedHashSet<>();
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
        Set<String> scopes = registeredClient.getScopes();
        for (String requestedScope : StringUtils.delimitedListToStringArray(scope, " ")) {
            if (scopes.contains(requestedScope)) {
                scopesToApprove.add(requestedScope);
            }
        }

        model.addAttribute("clientId", clientId);
        model.addAttribute("clientName", registeredClient.getClientName());
        model.addAttribute("state", state);
        model.addAttribute("scopes", scopesToApprove);
        model.addAttribute("principalName", principal.getName());
        model.addAttribute("redirectUri", registeredClient.getRedirectUris().iterator().next());

        model.addAttribute("codeChallenge", request.getParameter("code_challenge"));
        model.addAttribute("codeChallengeMethod", request.getParameter("code_challenge_method"));
        model.addAttribute("responseType", request.getParameter("response_type"));
        model.addAttribute("resource", request.getParameter("resource"));
        model.addAttribute("prompt", request.getParameter("prompt"));

        return "consent";
    }

    @PostMapping(value = "/oauth2/consent")
    public String processConsent(
            @RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
            @RequestParam(OAuth2ParameterNames.STATE) String state,
            @RequestParam(name = "user_oauth_approval", required = false) String approval,
            @RequestParam(name = "scope", required = false) List<String> scopes,
            HttpServletRequest request) {

        if (scopes != null && !scopes.isEmpty()) {
            // Build redirect URL for approval
            StringBuilder redirectUrl = new StringBuilder("/oauth2/authorize");
            redirectUrl.append("?client_id=").append(clientId);
            redirectUrl.append("&state=").append(state);
            redirectUrl.append("&response_type=code");

            RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
            String redirectUri = registeredClient.getRedirectUris().iterator().next();
            redirectUrl.append("&redirect_uri=").append(redirectUri);

            if (scopes != null && !scopes.isEmpty()) {
                redirectUrl.append("&scope=").append(String.join(" ", scopes));
            }

            return "redirect:" + redirectUrl.toString();
        } else {
            return "redirect:/oauth2/authorize?error=access_denied&state=" + state;
        }
    }
}