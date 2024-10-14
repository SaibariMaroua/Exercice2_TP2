package com.example.ex2_tp2.Controller;

import com.example.ex2_tp2.Service.CompteService;
import com.example.ex2_tp2.entities.Compte;
import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.servers.Server;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/v1/Comptes")
@OpenAPIDefinition(
        info = @Info(
                title = "Gestion des Comptes bancaire",
                description = "Gérer les opérations de banque",
                version = "1.0.0"
        ),
        servers = @Server(
                url = "http://localhost:8080/"
        )
)
public class CompteController {

    @Autowired
    CompteService compteService;

    @PostMapping
    @Operation(
            summary = "Ajouter Un compte",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    required = true,
                    content = @Content(
                            mediaType = "Application/json",
                            schema = @Schema(implementation = Compte.class)
                    )
            ),
            responses = {
                    @ApiResponse(responseCode = "200",
                            description = "ajout réussi",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = Compte.class))
                    ),
                    @ApiResponse(responseCode = "400", description = "erreur données"),
                    @ApiResponse(responseCode = "500", description = "erreur serveur")
            }
    )
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<Compte> add(@RequestBody Compte compte) {
        Compte compte1 = compteService.CreateCompte(compte);
        return ResponseEntity.ok(compte1);
    }

    @GetMapping
    @Operation(
            summary = "Récupérer Liste des Comptes",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Succès",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = Compte.class)
                            )
                    ),
                    @ApiResponse(responseCode = "400", description = "Paramètre d'entrée non valide")
            }
    )
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<List<Compte>> GetALL() {
        List<Compte> compteList = compteService.GetAllCompte();
        return ResponseEntity.ok(compteList);
    }

    @GetMapping("/{id}")
    @Operation(
            summary = "Récupérer un compte par son Id",
            parameters = @Parameter(
                    name = "id",
                    required = true
            ),
            responses = {
                    @ApiResponse(responseCode = "200",
                            description = "bien récupéré",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = Compte.class))
                    ),
                    @ApiResponse(responseCode = "404", description = "compte pas trouvé")
            }
    )

    public ResponseEntity<Compte> GetbyId(@PathVariable Long id) {
        Compte compte = compteService.GetCompteById(id);
        return compte == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(compte);
    }

    @DeleteMapping("/{id}")
    @Operation(
            summary = "Supprimer un compte par son Id",
            responses = {
                    @ApiResponse(responseCode = "200", description = "suppression réussie"),
                    @ApiResponse(responseCode = "404", description = "compte pas trouvé")
            }
    )
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<Void> Delete(@PathVariable Long id) {
        compteService.DeleteCompte(id);
        return ResponseEntity.ok().build();
    }

    @PutMapping("/{id}")
    @Operation(
            summary = "Modifier un compte par son Id",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    required = true,
                    content = @Content(
                            mediaType = "Application/json",
                            schema = @Schema(implementation = Compte.class)
                    )
            ),
            responses = {
                    @ApiResponse(responseCode = "200", description = "modification réussie"),
                    @ApiResponse(responseCode = "404", description = "compte pas trouvé")
            }
    )
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<Compte> Update(@PathVariable Long id, @RequestBody Compte c) {
        Compte compte = compteService.UpdateCompte(id, c);
        return ResponseEntity.ok(compte);
    }

    @GetMapping("/crediter/{id}/{m}")
    public ResponseEntity<Compte> crediter(@PathVariable Long id, @PathVariable float m) {
        Compte compte = compteService.Crediter(id, m);
        return ResponseEntity.ok(compte);
    }

    @GetMapping("/debiter/{id}/{m}")
    public ResponseEntity<Compte> debiter(@PathVariable Long id, @PathVariable float m) {
        Compte compte = compteService.Debiter(id, m);
        return ResponseEntity.ok(compte);
    }
}
