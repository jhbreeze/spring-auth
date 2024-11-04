package com.study.springauth.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import com.study.springauth.security.UserDetailsImpl;

@Controller
public class HomeController {

	@GetMapping("/")
	public String home(Model model, @AuthenticationPrincipal UserDetailsImpl userDetails) {
		// 페이지 동적 처리 : 사용자 이름
		model.addAttribute("username", userDetails.getUser().getUsername());

		return "index";
	}
}
