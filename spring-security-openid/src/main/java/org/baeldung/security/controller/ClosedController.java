package org.baeldung.security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class ClosedController {
    
    @RequestMapping("/closed")
    @ResponseBody
    public final String closed() {
        return "Welcome to closed";
    }

}
