package com.kafkamgt.uiapi.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kafkamgt.uiapi.UtilMethods;
import com.kafkamgt.uiapi.model.ServerConfigProperties;
import com.kafkamgt.uiapi.service.ServerConfigService;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class ServerConfigControllerTest {

    @MockBean
    private ServerConfigService serverConfigService;

    UtilMethods utilMethods;
    private MockMvc mvc;

    @BeforeEach
    public void setUp() {
        ServerConfigController serverConfigController = new ServerConfigController();
        mvc = MockMvcBuilders
                .standaloneSetup(serverConfigController)
                .dispatchOptions(true)
                .build();
        utilMethods = new UtilMethods();
        ReflectionTestUtils.setField(serverConfigController, "serverConfigService", serverConfigService);
    }

    @Test
    @Order(1)
    public void getAllServerConfig() throws Exception {
        List<ServerConfigProperties> serverConfigPropertiesList = utilMethods.getServerConfig();
        when(serverConfigService.getAllProps()).thenReturn(serverConfigPropertiesList);

        String res = mvc.perform(MockMvcRequestBuilders
                .get("/getAllServerConfig")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        List<ServerConfigProperties> response = new ObjectMapper().readValue(res, List.class);
        assertEquals(1, response.size());
    }
}