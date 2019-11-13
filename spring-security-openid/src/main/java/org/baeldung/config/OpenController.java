package org.baeldung.config;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class OpenController {
    
    @RequestMapping("/open")
    @ResponseBody
    public final String home() {
        return "Welcome to open";
    }

}
